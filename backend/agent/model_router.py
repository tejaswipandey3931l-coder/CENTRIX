"""Deterministic Model Router for CENTRIX AI Assessment System.

Enforces strict routing across verified FREE xKiro models only:
- MiniMax M3: Supervisor, planner, orchestration, multi-step decisions, final reasoning.
- Qwen3 Coder Plus: Source-code analysis, scanner analysis, remediation, workflows.
- Qwen3 VL Plus: Visual browser analysis, screenshots.
- Qwen3.5 Flash: Extraction (URLs, forms), log classification, summarization, deduplication.

NEVER routes to paid models.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .config import cfg, FREE_MODELS
from .errors import AgentError

TASK_TO_MODEL_MAP: dict[str, dict[str, str | int]] = {
    # Supervisor / Planning / Final Assessment
    "planning": {
        "model_key": "ai_primary_model",
        "reason": "MiniMax M3 selected for high-level assessment planning and global task coordination.",
        "context_limit": 128000,
    },
    "supervisor": {
        "model_key": "ai_primary_model",
        "reason": "MiniMax M3 selected for multi-step supervisory workflow orchestration.",
        "context_limit": 128000,
    },
    "final_assessment": {
        "model_key": "ai_primary_model",
        "reason": "MiniMax M3 selected for final comprehensive assessment synthesis.",
        "context_limit": 128000,
    },

    # Technical Reasoning / Remediation / Code
    "source_code": {
        "model_key": "ai_coding_model",
        "reason": "Qwen3 Coder Plus selected for technical source-code logic and validation.",
        "context_limit": 128000,
    },
    "scanner_analysis": {
        "model_key": "ai_coding_model",
        "reason": "Qwen3 Coder Plus selected for complex scanner output interpretation.",
        "context_limit": 128000,
    },
    "remediation": {
        "model_key": "ai_coding_model",
        "reason": "Qwen3 Coder Plus selected for authoritative defensive remediation guidance.",
        "context_limit": 128000,
    },
    "workflow_creation": {
        "model_key": "ai_coding_model",
        "reason": "Qwen3 Coder Plus selected for technical testing workflow formulation.",
        "context_limit": 128000,
    },

    # Vision / Browser UI
    "screenshot_analysis": {
        "model_key": "ai_vision_model",
        "reason": "Qwen3 VL Plus selected for visual DOM and screenshot comprehension.",
        "context_limit": 32000,
    },
    "browser_vision": {
        "model_key": "ai_vision_model",
        "reason": "Qwen3 VL Plus selected for visual page state analysis.",
        "context_limit": 32000,
    },

    # Fast Extraction / Summaries / Deduplication
    "url_extraction": {
        "model_key": "ai_fast_model",
        "reason": "Qwen3.5 Flash selected for fast deterministic URL and endpoint extraction.",
        "context_limit": 64000,
    },
    "form_extraction": {
        "model_key": "ai_fast_model",
        "reason": "Qwen3.5 Flash selected for fast form parameter mapping.",
        "context_limit": 64000,
    },
    "log_classification": {
        "model_key": "ai_fast_model",
        "reason": "Qwen3.5 Flash selected for lightweight log filtering and classification.",
        "context_limit": 64000,
    },
    "finding_deduplication": {
        "model_key": "ai_fast_model",
        "reason": "Qwen3.5 Flash selected for rapid heuristic finding deduplication.",
        "context_limit": 64000,
    },
    "response_summarization": {
        "model_key": "ai_fast_model",
        "reason": "Qwen3.5 Flash selected for fast HTTP response summarization.",
        "context_limit": 64000,
    },
}

TOOL_TO_TASK: dict[str, str] = {
    "validate_target": "supervisor",
    "confirm_authorization": "supervisor",
    "crawl_target": "url_extraction",
    "discover_endpoints": "url_extraction",
    "discover_forms": "form_extraction",
    "analyze_technologies": "scanner_analysis",
    "select_scanner_modules": "scanner_analysis",
    "run_passive_analysis": "scanner_analysis",
    "launch_browser": "browser_vision",
    "list_captured_requests": "response_summarization",
    "get_proxy_status": "response_summarization",
    "search_threat_intelligence": "scanner_analysis",
    "enrich_finding": "remediation",
    "collect_evidence": "response_summarization",
    "generate_report": "final_assessment",
}

@dataclass
class RouteDecision:
    task_type: str
    model: str
    reason: str
    context_limit: int
    fallback_attempts: list[str] = field(default_factory=list)


class ModelRouter:
    def __init__(self):
        self._history: list[RouteDecision] = []

    def route(self, task_type: str, failed_models: Optional[list[str]] = None) -> RouteDecision:
        failed_models = failed_models or []
        spec = TASK_TO_MODEL_MAP.get(task_type)
        
        if not spec:
            # Safe default to primary planning model
            spec = {
                "model_key": "ai_primary_model",
                "reason": f"Default fallback to MiniMax M3 for general task: {task_type}",
                "context_limit": 128000,
            }

        model_attr = str(spec["model_key"])
        primary_model = getattr(cfg, model_attr)

        if primary_model not in FREE_MODELS:
            raise AgentError(f"Prohibited non-free model configured for {model_attr}: {primary_model}")

        # Check if primary model has failed
        if primary_model not in failed_models:
            decision = RouteDecision(
                task_type=task_type,
                model=primary_model,
                reason=str(spec["reason"]),
                context_limit=int(spec["context_limit"]),
                fallback_attempts=list(failed_models),
            )
            self._history.append(decision)
            return decision

        # Safe fallback among ONLY FREE MODELS
        # E.g. If fast model fails, try coding or primary free model
        candidate_fallbacks = [
            cfg.ai_primary_model,
            cfg.ai_coding_model,
            cfg.ai_fast_model,
        ]

        for candidate in candidate_fallbacks:
            if candidate not in failed_models and candidate in FREE_MODELS:
                decision = RouteDecision(
                    task_type=task_type,
                    model=candidate,
                    reason=f"Free fallback model {candidate} selected after failure of {failed_models}",
                    context_limit=64000,
                    fallback_attempts=list(failed_models),
                )
                self._history.append(decision)
                return decision

        raise AgentError(
            f"All suitable free xKiro models failed or exhausted for task '{task_type}'. "
            f"Failed attempts: {failed_models}. Safely pausing agent session."
        )

    def get_history(self) -> list[RouteDecision]:
        return list(self._history)

    def route_tool(self, tool_name: str) -> RouteDecision:
        return self.route(TOOL_TO_TASK.get(tool_name, "supervisor"))


model_router = ModelRouter()
