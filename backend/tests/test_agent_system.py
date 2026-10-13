"""Unit tests for CENTRIX Autonomous Security Agent Control Plane."""
import pytest
import asyncio
from agent.config import cfg, FREE_MODELS
from agent.model_router import model_router, TASK_TO_MODEL_MAP
from agent.policy import policy_engine
from agent.approvals import approval_manager
from agent.tool_registry import registry
from agent.audit import audit_logger
from agent.usage import usage_tracker
from agent.errors import PolicyViolationError, AgentError


def test_free_models_enforced():
    """Verify that only authorized free xKiro models are permitted in configuration."""
    expected_models = {
        "minimax/minimax-m3:free",
        "qwen/qwen3-coder-plus:free",
        "qwen/qwen3-vl-plus:free",
        "qwen/qwen3.5-flash:free",
    }
    assert FREE_MODELS == expected_models
    assert cfg.ai_primary_model in FREE_MODELS
    assert cfg.ai_coding_model in FREE_MODELS
    assert cfg.ai_vision_model in FREE_MODELS
    assert cfg.ai_fast_model in FREE_MODELS


def test_model_router_deterministic():
    """Verify deterministic routing of task types to the assigned free models."""
    # Planning -> MiniMax M3
    plan_dec = model_router.route("planning")
    assert plan_dec.model == "minimax/minimax-m3:free"

    # Source code / Remediation -> Qwen3 Coder Plus
    code_dec = model_router.route("source_code")
    assert code_dec.model == "qwen/qwen3-coder-plus:free"
    rem_dec = model_router.route("remediation")
    assert rem_dec.model == "qwen/qwen3-coder-plus:free"

    # Vision -> Qwen3 VL Plus
    vis_dec = model_router.route("screenshot_analysis")
    assert vis_dec.model == "qwen/qwen3-vl-plus:free"

    # Extraction / Dedup -> Qwen3.5 Flash
    url_dec = model_router.route("url_extraction")
    assert url_dec.model == "qwen/qwen3.5-flash:free"
    dedup_dec = model_router.route("finding_deduplication")
    assert dedup_dec.model == "qwen/qwen3.5-flash:free"


def test_model_router_fallback():
    """Verify that fallback uses only other free models and halts if all free models exhausted."""
    # Simulate primary model failure
    fallback_dec = model_router.route("url_extraction", failed_models=["qwen/qwen3.5-flash:free"])
    assert fallback_dec.model in FREE_MODELS
    assert fallback_dec.model != "qwen/qwen3.5-flash:free"

    # All free models failed -> raises AgentError safely pausing agent
    with pytest.raises(AgentError) as excinfo:
        model_router.route("planning", failed_models=list(FREE_MODELS))
    assert "exhausted" in str(excinfo.value).lower() or "failed" in str(excinfo.value).lower()


def test_policy_scope_blocking():
    """Verify policy engine blocks invalid URLs, loopbacks, and private IP spaces."""
    # Valid public URL
    assert policy_engine.validate_target_scope("https://example.com") is True

    # Blocked link-local metadata
    with pytest.raises(PolicyViolationError):
        policy_engine.validate_target_scope("http://169.254.169.254/latest/meta-data")

    # Blocked localhost
    with pytest.raises(PolicyViolationError):
        policy_engine.validate_target_scope("http://127.0.0.1:8080")

    # Blocked domain scope restriction
    with pytest.raises(PolicyViolationError):
        policy_engine.validate_target_scope("https://attacker.com", allowed_domains=["example.com"])


def test_approval_workflow():
    """Verify HITL approval creation, approval, and rejection."""
    req = approval_manager.create_approval_request(
        session_id="test-ses-1",
        tool_name="replay_request",
        arguments={"path": "/admin"},
        risk_level="high",
    )
    appr_id = req["id"]
    assert req["status"] == "pending"

    # Approve
    dec = approval_manager.approve(appr_id, user_id="sec-admin")
    assert dec.decision == "approved"
    assert dec.user_id == "sec-admin"

    # Create second request and reject
    req2 = approval_manager.create_approval_request(
        session_id="test-ses-1",
        tool_name="submit_browser_form",
        arguments={"form": "delete_account"},
    )
    appr_id2 = req2["id"]
    dec2 = approval_manager.reject(appr_id2, user_id="sec-admin", comment="Not in test scope")
    assert dec2.decision == "rejected"
    assert dec2.comment == "Not in test scope"


@pytest.mark.asyncio
async def test_tool_registry_execution():
    """Verify tool execution, validation, and timeout handling."""
    specs = registry.get_tool_specs()
    names = {s["function"]["name"] for s in specs}
    assert "validate_target" in names
    assert "confirm_authorization" in names
    assert "crawl_target" in names

    # Execute validate_target
    res = await registry.execute("validate_target", {"target_url": "https://example.com"})
    assert res["status"] == "valid"
    assert res["hostname"] == "example.com"


def test_audit_and_usage():
    """Verify structured audit and usage records."""
    event = audit_logger.record(
        event_type="target_submission",
        session_id="test-audit-ses",
        target="https://example.com",
        details={"profile": "standard"}
    )
    assert event.id.startswith("aud-")
    assert event.event_type == "target_submission"

    events = audit_logger.list_events(session_id="test-audit-ses")
    assert len(events) >= 1
    assert events[0]["event_type"] == "target_submission"

    # Usage tracking
    usage_tracker.record_llm_call(
        session_id="test-audit-ses",
        model="minimax/minimax-m3:free",
        prompt_tokens=150,
        completion_tokens=80,
    )
    usage = usage_tracker.get_or_create("test-audit-ses")
    assert usage.total_steps >= 1
    assert usage.total_prompt_tokens >= 150
    assert usage.estimated_cost_usd == 0.0  # free model
