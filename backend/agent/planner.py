"""CENTRIX Assessment Planner using MiniMax M3."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .config import cfg
from .models import AssessmentPlan, AssessmentPlanStep, AgentMessage, AgentMessageRole
from .model_router import model_router
from .provider_client import provider_client
from .errors import AgentError
from .audit import audit_logger
from .events import agent_events


PLANNER_SYSTEM_PROMPT = """You are the Lead Assessment Planner for CENTRIX Autonomous Security System.
Your job is to analyze the target URL and generate a phased, compliant, passive-first security assessment roadmap.
You must return a JSON object with:
{
  "summary": "Brief explanation of assessment approach",
  "steps": [
    {
      "id": "step-1",
      "specialist": "Supervisor/Planner Agent",
      "objective": "Validate scope and verify authorization",
      "tools": ["validate_target", "confirm_authorization"]
    },
    {
      "id": "step-2",
      "specialist": "Reconnaissance Agent",
      "objective": "Passively crawl and discover target endpoints and tech stack",
      "tools": ["crawl_target", "discover_endpoints", "analyze_technologies"]
    },
    {
      "id": "step-3",
      "specialist": "Scanner Selection Agent",
      "objective": "Select passive configuration check modules",
      "tools": ["select_scanner_modules", "run_passive_analysis"]
    },
    {
      "id": "step-4",
      "specialist": "Threat Intelligence Agent",
      "objective": "Enrich findings with CVE threat intelligence",
      "tools": ["search_threat_intelligence", "enrich_finding"]
    },
    {
      "id": "step-5",
      "specialist": "Report Agent",
      "objective": "Synthesize findings and compile executive report",
      "tools": ["generate_report"]
    }
  ]
}
Respond ONLY with valid JSON.
"""

class Planner:
    async def create_plan(
        self,
        target_url: str,
        session_id: str = "sys",
        organization_id: str = "default-org",
        user_id: str = "operator"
    ) -> AssessmentPlan:
        # Route to primary planning model (MiniMax M3 free)
        route_decision = model_router.route(task_type="planning")
        
        audit_logger.record(
            event_type="plan_creation_start",
            session_id=session_id,
            organization_id=organization_id,
            user_id=user_id,
            target=target_url,
            details={"model": route_decision.model, "reason": route_decision.reason},
        )
        
        await agent_events.publish("agent_log", {
            "session_id": session_id,
            "message": f"Formulating assessment plan using {route_decision.model}...",
            "specialist": "Supervisor/Planner Agent",
            "model": route_decision.model
        })

        messages = [
            AgentMessage(role=AgentMessageRole.SYSTEM, content=PLANNER_SYSTEM_PROMPT),
            AgentMessage(
                role=AgentMessageRole.USER,
                content=f"Create a compliant assessment plan for target: {target_url}"
            ),
        ]

        try:
            resp = await provider_client.chat_completions(
                messages=messages,
                model=route_decision.model
            )
            raw_text = resp["choices"][0]["message"]["content"]
            # Clean markdown code blocks if any
            clean_json = raw_text.strip()
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            clean_json = clean_json.strip()
            
            data = json.loads(clean_json)
            steps = [AssessmentPlanStep(**s) for s in data.get("steps", [])]
            plan = AssessmentPlan(
                target=target_url,
                summary=data.get("summary", "Standard phased passive security assessment"),
                steps=steps
            )
        except Exception as exc:
            # Fallback deterministic compliant plan if LLM is unavailable or unparseable
            plan = AssessmentPlan(
                target=target_url,
                summary="Compliant baseline assessment plan (deterministic fallback)",
                steps=[
                    AssessmentPlanStep(
                        id="step-1",
                        specialist="Supervisor/Planner Agent",
                        objective="Validate target structure and verify authorization",
                        tools=["validate_target", "confirm_authorization"],
                    ),
                    AssessmentPlanStep(
                        id="step-2",
                        specialist="Reconnaissance Agent",
                        objective="Passively map endpoints and detect technology stack",
                        tools=["crawl_target", "discover_endpoints", "analyze_technologies"],
                    ),
                    AssessmentPlanStep(
                        id="step-3",
                        specialist="Scanner Selection Agent",
                        objective="Select and run passive configuration checks",
                        tools=["select_scanner_modules", "run_passive_analysis"],
                    ),
                    AssessmentPlanStep(
                        id="step-4",
                        specialist="Threat Intelligence Agent",
                        objective="Correlate detected tech stack with known advisories",
                        tools=["search_threat_intelligence", "enrich_finding"],
                    ),
                    AssessmentPlanStep(
                        id="step-5",
                        specialist="Report Agent",
                        objective="Generate executive remediation and retest report",
                        tools=["generate_report"],
                    ),
                ]
            )

        audit_logger.record(
            event_type="plan_creation_success",
            session_id=session_id,
            organization_id=organization_id,
            user_id=user_id,
            target=target_url,
            details={"steps_count": len(plan.steps)},
        )

        return plan


planner = Planner()
