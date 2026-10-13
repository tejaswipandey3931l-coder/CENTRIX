"""Human-In-The-Loop (HITL) Approval Management System."""
from __future__ import annotations

import datetime
import uuid
from typing import Any, Optional
from pydantic import BaseModel, Field

from .errors import AgentError


class ApprovalDecision(BaseModel):
    approval_id: str
    decision: str  # "approved" or "rejected"
    user_id: str = "operator"
    comment: Optional[str] = None
    decided_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


class ApprovalManager:
    def __init__(self):
        self._pending: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, ApprovalDecision] = {}

    def create_approval_request(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk_level: str = "medium",
        justification: str = "Action requires operator confirmation before execution.",
    ) -> dict[str, Any]:
        approval_id = f"appr-{uuid.uuid4().hex[:8]}"
        req = {
            "id": approval_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "risk_level": risk_level,
            "justification": justification,
            "status": "pending",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._pending[approval_id] = req
        return req

    def get_pending(self, approval_id: str) -> Optional[dict[str, Any]]:
        return self._pending.get(approval_id)

    def list_pending_for_session(self, session_id: str) -> list[dict[str, Any]]:
        return [r for r in self._pending.values() if r["session_id"] == session_id and r["status"] == "pending"]

    def approve(self, approval_id: str, user_id: str = "operator", comment: Optional[str] = None) -> ApprovalDecision:
        if approval_id not in self._pending:
            raise AgentError(f"Approval request {approval_id} not found.")
        req = self._pending[approval_id]
        if req["status"] != "pending":
            raise AgentError(f"Approval request {approval_id} is already {req['status']}.")

        req["status"] = "approved"
        decision = ApprovalDecision(
            approval_id=approval_id,
            decision="approved",
            user_id=user_id,
            comment=comment,
        )
        self._decisions[approval_id] = decision
        return decision

    def reject(self, approval_id: str, user_id: str = "operator", comment: Optional[str] = None) -> ApprovalDecision:
        if approval_id not in self._pending:
            raise AgentError(f"Approval request {approval_id} not found.")
        req = self._pending[approval_id]
        if req["status"] != "pending":
            raise AgentError(f"Approval request {approval_id} is already {req['status']}.")

        req["status"] = "rejected"
        decision = ApprovalDecision(
            approval_id=approval_id,
            decision="rejected",
            user_id=user_id,
            comment=comment,
        )
        self._decisions[approval_id] = decision
        return decision


approval_manager = ApprovalManager()
