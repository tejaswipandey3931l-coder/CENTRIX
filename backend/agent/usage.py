"""Agent Resource and Model Usage Accounting Tracker."""
from __future__ import annotations

import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

from db.store import _connection, _init_db, _json


class SessionUsage(BaseModel):
    session_id: str
    organization_id: str = "default-org"
    user_id: str = "operator"
    total_steps: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    estimated_cost_usd: float = 0.0  # 0.0 for authorized free models
    model_invocations: dict[str, int] = Field(default_factory=dict)
    tool_invocations: dict[str, int] = Field(default_factory=dict)
    browser_actions: int = 0
    crawl_requests: int = 0
    scanner_executions: int = 0
    approvals_requested: int = 0
    approvals_granted: int = 0
    approvals_rejected: int = 0
    updated_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


class UsageTracker:
    def __init__(self):
        self._init_table()

    def _init_table(self):
        _init_db()
        with _connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_usage (
                    session_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            """)

    def record_llm_call(
        self,
        session_id: str,
        model: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        organization_id: str = "default-org",
        user_id: str = "operator",
    ) -> None:
        usage = self.get_or_create(session_id, organization_id, user_id)
        usage.total_prompt_tokens += prompt_tokens
        usage.total_completion_tokens += completion_tokens
        usage.model_invocations[model] = usage.model_invocations.get(model, 0) + 1
        usage.total_steps += 1
        # Free xKiro models cost $0.00
        usage.estimated_cost_usd = 0.0
        self._save(usage)

    def record_tool_call(
        self,
        session_id: str,
        tool_name: str,
        organization_id: str = "default-org",
        user_id: str = "operator",
    ) -> None:
        usage = self.get_or_create(session_id, organization_id, user_id)
        usage.tool_invocations[tool_name] = usage.tool_invocations.get(tool_name, 0) + 1
        
        if "browser" in tool_name:
            usage.browser_actions += 1
        elif "crawl" in tool_name or "discover" in tool_name:
            usage.crawl_requests += 1
        elif "scanner" in tool_name or "nuclei" in tool_name:
            usage.scanner_executions += 1
            
        self._save(usage)

    def record_approval(self, session_id: str, decision: str) -> None:
        usage = self.get_or_create(session_id)
        usage.approvals_requested += 1
        if decision == "approved":
            usage.approvals_granted += 1
        elif decision == "rejected":
            usage.approvals_rejected += 1
        self._save(usage)

    def get_or_create(self, session_id: str, organization_id: str = "default-org", user_id: str = "operator") -> SessionUsage:
        self._init_table()
        with _connection() as conn:
            row = conn.execute("SELECT payload FROM agent_usage WHERE session_id = ?", (session_id,)).fetchone()
        if row:
            import json
            return SessionUsage.model_validate(json.loads(row["payload"]))
        return SessionUsage(session_id=session_id, organization_id=organization_id, user_id=user_id)

    def _save(self, usage: SessionUsage) -> None:
        self._init_table()
        with _connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agent_usage (session_id, organization_id, user_id, payload)
                VALUES (?, ?, ?, ?)
                """,
                (usage.session_id, usage.organization_id, usage.user_id, _json(usage.model_dump(mode="json"))),
            )

    def get_aggregate_usage(self, organization_id: str = "default-org") -> dict[str, Any]:
        self._init_table()
        with _connection() as conn:
            rows = conn.execute("SELECT payload FROM agent_usage WHERE organization_id = ?", (organization_id,)).fetchall()
        
        import json
        all_usages = [SessionUsage.model_validate(json.loads(r["payload"])) for r in rows]
        
        return {
            "organization_id": organization_id,
            "total_sessions": len(all_usages),
            "total_prompt_tokens": sum(u.total_prompt_tokens for u in all_usages),
            "total_completion_tokens": sum(u.total_completion_tokens for u in all_usages),
            "estimated_cost_usd": 0.0,
            "total_browser_actions": sum(u.browser_actions for u in all_usages),
            "total_crawl_requests": sum(u.crawl_requests for u in all_usages),
            "total_scanner_executions": sum(u.scanner_executions for u in all_usages),
            "total_approvals": sum(u.approvals_requested for u in all_usages),
        }


usage_tracker = UsageTracker()
