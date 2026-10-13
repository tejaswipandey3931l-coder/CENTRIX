"""Data models and SQLite persistence for CENTRIX Agent Sessions."""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from enum import Enum
import uuid
import datetime
import json

from db.store import _connection, _init_db, _json, _get_lock


class SessionStatus(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"      # e.g. Waiting for human approval
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class AgentMessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCallRequest(BaseModel):
    id: str
    type: Literal["function"] = "function"
    function: Dict[str, Any]


class AgentMessage(BaseModel):
    role: AgentMessageRole
    content: str | None = None
    tool_calls: Optional[List[ToolCallRequest]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:8]}")
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "medium"
    justification: str = "Operation requires operator confirmation."
    status: Literal["pending", "approved", "rejected"] = "pending"
    created_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    decided_at: Optional[datetime.datetime] = None
    decided_by: Optional[str] = None


class AssessmentPlanStep(BaseModel):
    id: str
    specialist: str
    objective: str
    tools: List[str] = Field(default_factory=list)
    status: Literal["pending", "running", "completed", "skipped"] = "pending"


class AssessmentPlan(BaseModel):
    target: str
    created_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    steps: List[AssessmentPlanStep] = Field(default_factory=list)
    summary: str = ""


class AssessmentSession(BaseModel):
    id: str = Field(default_factory=lambda: f"ses-{uuid.uuid4().hex[:10]}")
    target_url: str
    scope_domains: List[str] = Field(default_factory=list)
    safety_profile: str = "standard"
    status: SessionStatus = SessionStatus.CREATED
    organization_id: str = "default-org"
    user_id: str = "operator"
    scan_id: Optional[str] = None
    
    current_stage: str = "initialization"
    current_specialist: str = "Supervisor/Planner Agent"
    current_model: str = "minimax/minimax-m3:free"
    
    plan: Optional[AssessmentPlan] = None
    pending_approval: Optional[ApprovalRequest] = None
    
    discovered_urls: List[str] = Field(default_factory=list)
    discovered_forms: List[Dict[str, Any]] = Field(default_factory=list)
    captured_requests_count: int = 0
    selected_scanner_modules: List[str] = Field(default_factory=list)
    findings_count: int = 0
    evidence_count: int = 0
    
    browser_status: str = "idle"
    proxy_status: str = "active"
    step_count: int = 0
    stop_reason: Optional[str] = None
    
    messages: List[AgentMessage] = Field(default_factory=list)
    tool_history: List[Dict[str, Any]] = Field(default_factory=list)
    
    created_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


# --- Database Persistence for Sessions ---

def _init_agent_tables() -> None:
    _init_db()
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)


async def save_session(session: AssessmentSession) -> None:
    async with _get_lock():
        _init_agent_tables()
        session.updated_at = datetime.datetime.now(datetime.timezone.utc)
        payload = _json(session.model_dump(mode="json"))
        with _connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agent_sessions (id, organization_id, user_id, target_url, status, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.organization_id,
                    session.user_id,
                    session.target_url,
                    session.status.value,
                    payload,
                    session.updated_at.isoformat(),
                ),
            )


async def get_session(session_id: str, organization_id: Optional[str] = None) -> Optional[AssessmentSession]:
    _init_agent_tables()
    with _connection() as conn:
        if organization_id:
            row = conn.execute(
                "SELECT payload FROM agent_sessions WHERE id = ? AND organization_id = ?",
                (session_id, organization_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT payload FROM agent_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
    if not row:
        return None
    data = json.loads(row["payload"])
    return AssessmentSession.model_validate(data)


async def list_sessions(organization_id: str = "default-org", limit: int = 50) -> List[AssessmentSession]:
    _init_agent_tables()
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT payload FROM agent_sessions 
            WHERE organization_id = ? 
            ORDER BY updated_at DESC LIMIT ?
            """,
            (organization_id, limit),
        ).fetchall()
    return [AssessmentSession.model_validate(json.loads(r["payload"])) for r in rows]
