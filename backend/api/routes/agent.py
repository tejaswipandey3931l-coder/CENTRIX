"""CENTRIX Autonomous Security Agent API Endpoints."""
from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel, Field

from agent.models import (
    AssessmentSession,
    save_session,
    get_session,
    list_sessions,
)
from agent.orchestrator import orchestrator
from agent.config import cfg, FREE_MODELS
from agent.audit import audit_logger
from agent.usage import usage_tracker
from agent.events import agent_events
from agent.policy import policy_engine
from agent.model_router import TASK_TO_MODEL_MAP


router = APIRouter(prefix="", tags=["Autonomous Agent"])

_LOCAL_ORG = os.getenv("CENTRIX_ORGANIZATION_ID", "local-org")
_LOCAL_USER = os.getenv("CENTRIX_OPERATOR_ID", "local-operator")
_OPERATOR_TOKEN = os.getenv("CENTRIX_OPERATOR_TOKEN", "").strip()

def _identity(request: Request) -> tuple[str, str]:
    if _OPERATOR_TOKEN and request.headers.get("authorization", "") != f"Bearer {_OPERATOR_TOKEN}":
        raise HTTPException(status_code=401, detail="Valid CENTRIX_OPERATOR_TOKEN is required")
    return _LOCAL_ORG, _LOCAL_USER

async def _owned(session_id: str, request: Request) -> AssessmentSession:
    organization_id, user_id = _identity(request)
    session = await get_session(session_id, organization_id=organization_id)
    if not session or session.user_id != user_id:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return session


class CreateSessionRequest(BaseModel):
    target_url: str
    scope_domains: List[str] = Field(default_factory=list)
    safety_profile: str = "standard"


class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    user_id: str = "operator"
    comment: Optional[str] = None


class ActionReasonRequest(BaseModel):
    reason: str = "Operator manual command"


# --- Agent Session Management ---

@router.post("/api/agent/sessions", response_model=AssessmentSession)
async def create_agent_session(req: CreateSessionRequest, request: Request):
    organization_id, user_id = _identity(request)
    try:
        policy_engine.validate_target_scope(req.target_url, req.scope_domains)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    session = AssessmentSession(
        target_url=req.target_url,
        scope_domains=req.scope_domains,
        safety_profile=req.safety_profile,
        organization_id=organization_id,
        user_id=user_id,
    )
    await save_session(session)
    
    audit_logger.record(
        event_type="target_submission",
        session_id=session.id,
        organization_id=session.organization_id,
        user_id=session.user_id,
        target=session.target_url,
        details={"safety_profile": session.safety_profile},
    )
    return session


@router.get("/api/agent/sessions", response_model=List[AssessmentSession])
async def list_agent_sessions(request: Request):
    organization_id, _ = _identity(request)
    return await list_sessions(organization_id=organization_id)


@router.get("/api/agent/sessions/{session_id}", response_model=AssessmentSession)
async def get_agent_session(session_id: str, request: Request):
    return await _owned(session_id, request)


@router.post("/api/agent/sessions/{session_id}/start", response_model=AssessmentSession)
async def start_agent_session(session_id: str, request: Request):
    try:
        await _owned(session_id, request)
        return await orchestrator.start_session(session_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/agent/sessions/{session_id}/pause", response_model=AssessmentSession)
async def pause_agent_session(session_id: str, req: ActionReasonRequest, request: Request):
    try:
        await _owned(session_id, request)
        return await orchestrator.pause_session(session_id, reason=req.reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/agent/sessions/{session_id}/resume", response_model=AssessmentSession)
async def resume_agent_session(session_id: str, request: Request):
    try:
        await _owned(session_id, request)
        return await orchestrator.resume_session(session_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/agent/sessions/{session_id}/stop", response_model=AssessmentSession)
async def stop_agent_session(session_id: str, req: ActionReasonRequest, request: Request):
    try:
        await _owned(session_id, request)
        return await orchestrator.stop_session(session_id, reason=req.reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/agent/sessions/{session_id}/approve", response_model=AssessmentSession)
async def approve_agent_action(session_id: str, req: ApprovalDecisionRequest, request: Request):
    try:
        _, user_id = _identity(request)
        await _owned(session_id, request)
        return await orchestrator.approve_action(session_id, req.approval_id, user_id=user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/api/agent/sessions/{session_id}/reject", response_model=AssessmentSession)
async def reject_agent_action(session_id: str, req: ApprovalDecisionRequest, request: Request):
    try:
        _, user_id = _identity(request)
        await _owned(session_id, request)
        return await orchestrator.reject_action(session_id, req.approval_id, user_id=user_id, reason=req.comment or "")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/api/agent/sessions/{session_id}/events")
async def get_agent_session_events(session_id: str, request: Request, limit: int = 50):
    session = await _owned(session_id, request)
    return audit_logger.list_events(session_id=session.id, organization_id=session.organization_id, limit=limit)


# --- AI Health, Models & Usage ---

@router.get("/api/ai/health")
async def ai_health():
    key_configured = bool(cfg.xkiro_api_key and cfg.xkiro_api_key != "your_key_here")
    return {
        "status": "operational" if key_configured else "configured_without_api_key",
        "provider": cfg.ai_provider,
        "base_url": cfg.ai_base_url,
        "free_models_enforced": True,
        "allowed_models": list(FREE_MODELS),
    }


@router.get("/api/ai/models")
async def list_ai_models():
    return {
        "models": [
            {
                "id": m,
                "tier": "free",
                "provider": "xkiro",
            }
            for m in FREE_MODELS
        ],
        "routing_matrix": {
            task: {
                "model": getattr(cfg, str(info["model_key"])),
                "reason": info["reason"]
            }
            for task, info in TASK_TO_MODEL_MAP.items()
        }
    }


@router.get("/api/ai/usage")
async def get_ai_usage(request: Request):
    organization_id, _ = _identity(request)
    return usage_tracker.get_aggregate_usage(organization_id=organization_id)


@router.get("/api/audit/events")
async def list_audit_events(request: Request, limit: int = 100):
    organization_id, _ = _identity(request)
    return audit_logger.list_events(organization_id=organization_id, limit=limit)


# --- WebSocket for Real-Time Agent Stream ---

@router.websocket("/api/agent/ws/{session_id}")
async def agent_websocket(websocket: WebSocket, session_id: str):
    if _OPERATOR_TOKEN and websocket.headers.get("authorization", "") != f"Bearer {_OPERATOR_TOKEN}":
        await websocket.close(code=1008, reason="Authentication required")
        return
    session = await get_session(session_id, organization_id=_LOCAL_ORG)
    if not session or session.user_id != _LOCAL_USER:
        await websocket.close(code=1008, reason="Session not found")
        return
    await websocket.accept()
    
    queue: asyncio.Queue = asyncio.Queue()

    async def _on_event(payload: Any):
        if isinstance(payload, dict) and payload.get("session_id") in (session_id, None):
            await queue.put(payload)

    agent_events.subscribe("agent_log", _on_event)
    agent_events.subscribe("session_update", _on_event)

    try:
        while True:
            # Send live events to client
            data = await queue.get()
            await websocket.send_json(data)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        agent_events.unsubscribe("agent_log", _on_event)
        agent_events.unsubscribe("session_update", _on_event)
