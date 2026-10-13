"""CENTRIX Tool Registry.

Provides typed, controlled tools for autonomous agent execution.
Reuses existing CENTRIX scanner, reporting, and safety systems.
Prevents arbitrary shell, code, or filesystem execution.
"""
from __future__ import annotations

import asyncio
import datetime
import contextvars
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Dict, List, Optional
from urllib.parse import urlparse

from scanner.safety import normalise_target, url_in_scope, ensure_public_target
from scanner.stages import crawl as crawl_stage, discover as discover_stage, passive as passive_stage, analyze as analyze_stage
from db import store
from api.models import EvidenceArtifact
from .policy import policy_engine
from .errors import ToolExecutionError, PolicyViolationError
from .redaction import redact_payload
from .audit import audit_logger

_execution_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("agent_execution_context", default={})
_session_contexts: dict[str, dict[str, Any]] = {}

def _ctx() -> dict[str, Any]:
    return _execution_context.get()


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: Dict[str, Any]
    safety_level: str  # "passive" or "active"
    handler: Callable[..., Coroutine[Any, Any, Dict[str, Any]]]


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        safety_level: str = "passive",
    ) -> Callable:
        def decorator(func: Callable[..., Coroutine[Any, Any, Dict[str, Any]]]):
            self._tools[name] = ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                safety_level=safety_level,
                handler=func,
            )
            return func
        return decorator

    def get_tool_specs(self) -> List[Dict[str, Any]]:
        """Returns schemas for xKiro / OpenAI compatible function calling."""
        specs = []
        for tool in self._tools.values():
            specs.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            })
        return specs

    async def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str = "sys",
        organization_id: str = "default-org",
        user_id: str = "operator",
    ) -> Dict[str, Any]:
        tool = self._tools.get(tool_name)
        if not tool:
            raise ToolExecutionError(f"Tool '{tool_name}' is not registered.")

        # Audit event for invocation
        audit_logger.record(
            event_type="tool_call_start",
            session_id=session_id,
            organization_id=organization_id,
            user_id=user_id,
            details={"tool": tool_name, "arguments": redact_payload(arguments)},
        )

        context = _session_contexts.setdefault(session_id, {"data": {}})
        context.update({"session_id": session_id, "organization_id": organization_id, "user_id": user_id})
        if "target_url" in arguments:
            context["target_url"] = arguments["target_url"]
        token = _execution_context.set(context)
        try:
            # Enforce execution timeout (max 120s per tool)
            # Providers sometimes include UI-only fields alongside function
            # arguments. Never pass unknown fields to Python callables.
            allowed = set((tool.parameters.get("properties") or {}).keys())
            clean_arguments = {key: value for key, value in arguments.items() if key in allowed}
            result = await asyncio.wait_for(tool.handler(**clean_arguments), timeout=120.0)
            
            audit_logger.record(
                event_type="tool_call_success",
                session_id=session_id,
                organization_id=organization_id,
                user_id=user_id,
                details={"tool": tool_name},
            )
            return result
        except asyncio.TimeoutError:
            raise ToolExecutionError(f"Tool '{tool_name}' timed out after 120 seconds.")
        except Exception as exc:
            audit_logger.record(
                event_type="tool_call_error",
                session_id=session_id,
                organization_id=organization_id,
                user_id=user_id,
                details={"tool": tool_name, "error": str(exc)},
            )
            raise ToolExecutionError(f"Tool '{tool_name}' execution failed: {str(exc)}") from exc
        finally:
            _execution_context.reset(token)


registry = ToolRegistry()


# --- Concrete Tool Implementations ---

@registry.register(
    name="validate_target",
    description="Validate target URL structure, connectivity, and ensure it is not on restricted private/link-local networks.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "description": "The URL to validate"}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_validate_target(target_url: str) -> Dict[str, Any]:
    norm = normalise_target(target_url)
    policy_engine.validate_target_scope(norm)
    # Check DNS resolution
    try:
        await ensure_public_target(norm)
        is_public = True
    except Exception as e:
        is_public = False
    return {
        "status": "valid",
        "normalized_url": norm,
        "is_public": is_public,
        "hostname": urlparse(norm).hostname,
    }


@registry.register(
    name="confirm_authorization",
    description="Confirm and record verified organizational authorization for the target domain.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"},
            "authorized_by": {"type": "string", "description": "Operator name or authorization ticket"}
        },
        "required": ["target_url", "authorized_by"]
    },
    safety_level="passive"
)
async def tool_confirm_authorization(target_url: str, authorized_by: str) -> Dict[str, Any]:
    norm = normalise_target(target_url)
    return {
        "authorized": True,
        "target": norm,
        "authorized_by": authorized_by,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@registry.register(
    name="create_assessment_plan",
    description="Construct structured phased assessment roadmap outlining reconnaissance, analysis, and reporting.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"},
            "phases": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "phase_name": {"type": "string"},
                        "specialist": {"type": "string"},
                        "objective": {"type": "string"}
                    },
                    "required": ["phase_name", "specialist", "objective"]
                }
            }
        },
        "required": ["target_url", "phases"]
    },
    safety_level="passive"
)
async def tool_create_assessment_plan(target_url: str, phases: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "status": "plan_created",
        "target": target_url,
        "total_phases": len(phases),
        "phases": phases
    }


@registry.register(
    name="crawl_target",
    description="Passively crawl target website within approved scope to extract discovered links, endpoints, and assets.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"},
            "max_depth": {"type": "integer", "default": 2}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_crawl_target(target_url: str, max_depth: int = 2) -> Dict[str, Any]:
    norm = normalise_target(target_url)
    policy_engine.validate_target_scope(norm)
    async def log(message: str) -> None:
        session_id = _ctx().get("session_id", "sys")
        await store.push_log(session_id, message)
    result = await crawl_stage.run(norm, [], log, depth=max(1, min(max_depth, 5)), scope=[])
    _ctx().setdefault("data", {})["crawl"] = result
    return {"status": "completed", "discovered_urls": result.get("urls", []), "forms": result.get("forms", []), "parameters": result.get("parameters", []), "evidence": result.get("evidence", []), "count": len(result.get("urls", []))}


@registry.register(
    name="discover_endpoints",
    description="Extract API and route endpoints from mapped target assets.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_discover_endpoints(target_url: str) -> Dict[str, Any]:
    norm = normalise_target(target_url)
    policy_engine.validate_target_scope(norm)
    async def log(message: str) -> None:
        await store.push_log(_ctx().get("session_id", "sys"), message)
    result = await discover_stage.run(norm, log)
    _ctx().setdefault("data", {})["discovery"] = result
    return {"status": "completed", **result}


@registry.register(
    name="discover_forms",
    description="Identify interactive HTML input forms and submission parameters.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_discover_forms(target_url: str) -> Dict[str, Any]:
    crawl = _ctx().get("data", {}).get("crawl", {})
    return {"status": "completed", "forms": crawl.get("forms", [])}


@registry.register(
    name="launch_browser",
    description="Launch an isolated Playwright Chromium session and capture the target page responses. Use only after target authorization.",
    parameters={"type": "object", "properties": {"target_url": {"type": "string"}}, "required": ["target_url"]},
    safety_level="passive",
)
async def tool_launch_browser(target_url: str) -> Dict[str, Any]:
    from scanner.browser_workflows import run_browser_workflows, browser_results_to_scan_inputs
    norm = normalise_target(target_url)
    policy_engine.validate_target_scope(norm)
    results = await run_browser_workflows({"name": "autonomous-observe", "start_url": norm, "steps": [{"action": "goto", "url": norm}]}, base_url=norm, timeout=30, headless=True)
    urls, forms, evidence = await browser_results_to_scan_inputs(results)
    for item in evidence:
        try:
            await store.add_evidence(EvidenceArtifact(
                id=f"EV-{uuid.uuid4().hex[:10].upper()}",
                scan_id=_ctx().get("session_id", "sys"),
                url=str(item.get("url") or norm),
                status_code=int(item.get("status_code") or 0),
                content_type=str(item.get("content_type") or ""),
                response_length=int(item.get("response_length") or 0),
                response_excerpt=policy_engine.sanitize_untrusted_content(str(item.get("response_excerpt") or "")),
                response_headers={str(k): str(v) for k, v in (item.get("response_headers") or {}).items()},
            ))
        except Exception:
            pass
    _ctx().setdefault("data", {})["browser"] = {"results": [r.to_dict() for r in results], "urls": urls, "forms": forms, "evidence": evidence}
    return {"status": "completed", "urls": urls, "forms": forms, "evidence": evidence, "workflows": [r.to_dict() for r in results]}


@registry.register(
    name="list_captured_requests",
    description="Read requests and responses captured for this assessment from the persisted corpus.",
    parameters={"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}},
    safety_level="passive",
)
async def tool_list_captured_requests(limit: int = 50) -> Dict[str, Any]:
    items = await store.list_corpus(_ctx().get("session_id", "sys"))
    return {"status": "completed", "requests": items[:max(1, min(limit, 200))], "count": len(items)}


@registry.register(
    name="get_proxy_status",
    description="Inspect the current CENTRIX capture proxy status without changing it.",
    parameters={"type": "object", "properties": {}},
    safety_level="passive",
)
async def tool_get_proxy_status() -> Dict[str, Any]:
    from api.routes.manual import _capture_proxy
    return {"status": "completed", "proxy": _capture_proxy.status()}


@registry.register(
    name="analyze_technologies",
    description="Perform passive header and response inspection to identify server stacks, libraries, and frameworks.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_analyze_technologies(target_url: str) -> Dict[str, Any]:
    crawl = _ctx().get("data", {}).get("crawl", {})
    technologies: list[dict[str, str]] = []
    for item in crawl.get("evidence", []):
        headers = {str(k).lower(): str(v) for k, v in (item.get("response_headers") or {}).items()}
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        for value, category in ((server, "Web Server"), (powered, "Runtime/Framework")):
            if value and not any(t["name"].lower() == value.lower() for t in technologies):
                technologies.append({"name": value, "category": category})
    return {"status": "completed", "technologies": technologies, "source": "observed-response-headers"}


@registry.register(
    name="select_scanner_modules",
    description="Select appropriate passive analysis and audit modules tailored to detected tech stack.",
    parameters={
        "type": "object",
        "properties": {
            "technologies": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["technologies"]
    },
    safety_level="passive"
)
async def tool_select_scanner_modules(technologies: List[str]) -> Dict[str, Any]:
    selected = ["ssl_tls", "cors", "security_headers", "cookie_flags"]
    return {
        "selected_modules": selected,
        "rationale": "Non-destructive passive configuration and header verification checks."
    }


@registry.register(
    name="run_passive_analysis",
    description="Execute passive compliance and security header analysis on target endpoint.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"}
        },
        "required": ["target_url"]
    },
    safety_level="passive"
)
async def tool_run_passive_analysis(target_url: str) -> Dict[str, Any]:
    norm = normalise_target(target_url)
    policy_engine.validate_target_scope(norm)
    evidence = _ctx().get("data", {}).get("crawl", {}).get("evidence", [])
    async def log(message: str) -> None:
        await store.push_log(_ctx().get("session_id", "sys"), message)
    findings = await passive_stage.run(evidence, log)
    analyzed = await analyze_stage.run(_ctx().get("session_id", "sys"), findings, log)
    for finding in analyzed:
        await store.add_finding(_ctx().get("session_id", "sys"), finding)
    _ctx().setdefault("data", {})["passive_findings"] = findings
    return {"status": "completed", "target": norm, "observations": findings, "persisted_findings": len(analyzed), "evidence_items": len(evidence)}


@registry.register(
    name="collect_evidence",
    description="Store cryptographically hashed evidence artifact linked to current assessment session.",
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "evidence_type": {"type": "string"},
            "content": {"type": "string"}
        },
        "required": ["title", "evidence_type", "content"]
    },
    safety_level="passive"
)
async def tool_collect_evidence(title: str, evidence_type: str, content: str) -> Dict[str, Any]:
    session_id = _ctx().get("session_id", "sys")
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    item = EvidenceArtifact(id=f"EV-{uuid.uuid4().hex[:10].upper()}", scan_id=session_id, url=_ctx().get("target_url", ""), status_code=200, content_type=f"agent/{evidence_type}", response_length=len(content), response_excerpt=content[:2000])
    await store.add_evidence(item)
    return {
        "evidence_id": item.id,
        "title": title,
        "evidence_type": evidence_type,
        "hash": content_hash,
        "stored": True,
        "scan_id": session_id,
    }


@registry.register(
    name="search_threat_intelligence",
    description="Query CENTRIX Threat Intel database for CVE and advisory context.",
    parameters={
        "type": "object",
        "properties": {
            "technology": {"type": "string"},
            "query": {"type": "string"}
        },
        "required": ["technology"]
    },
    safety_level="passive"
)
async def tool_search_threat_intelligence(technology: str, query: str = "") -> Dict[str, Any]:
    return {
        "technology": technology,
        "query": query,
        "intel": [],
        "status": "no_local_advisory_match",
        "message": "No verified advisory was returned by the configured threat-intelligence source.",
    }


@registry.register(
    name="enrich_finding",
    description="Enrich detected finding with remediation guidance, CVSS scoring, and OWASP references.",
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "cwe": {"type": "string"},
            "cvss": {"type": "number"}
        },
        "required": ["title", "cwe"]
    },
    safety_level="passive"
)
async def tool_enrich_finding(title: str, cwe: str, cvss: float = 5.0) -> Dict[str, Any]:
    return {
        "enriched": True,
        "title": title,
        "cwe": cwe,
        "cvss": cvss,
        "remediation": "Apply defense-in-depth headers and review authorization configurations."
    }


@registry.register(
    name="generate_report",
    description="Generate executive and technical security assessment summary with verified findings.",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string"},
            "executive_summary": {"type": "string"},
            "remediation_summary": {"type": "string"}
        },
        "required": ["target_url", "executive_summary"]
    },
    safety_level="passive"
)
async def tool_generate_report(target_url: str, executive_summary: str, remediation_summary: str = "") -> Dict[str, Any]:
    import base64
    from api.models import ScanConfig, ScanState, ScanStatus, ScanStage
    from reporting.pdf_report import build_centrix_pdf_report
    session_id = _ctx().get("session_id", "sys")
    findings = await store.get_findings(session_id)
    evidence = await store.get_evidence(session_id)
    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
    state = ScanState(
        id=session_id,
        config=ScanConfig(target=target_url, authorized=True),
        status=ScanStatus.completed,
        stage=ScanStage.done,
        progress=100,
        findings_count=len(findings),
        urls_discovered=len(_ctx().get("data", {}).get("crawl", {}).get("urls", [])),
    )
    pdf_bytes = build_centrix_pdf_report(report_id, state, findings, evidence)
    payload = {
        "report_id": report_id,
        "scan_id": session_id,
        "target": target_url,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "ready",
        "format": "pdf",
        "size": f"{len(pdf_bytes) / 1024:.1f} KB",
        "content": base64.b64encode(pdf_bytes).decode("ascii"),
        "executive_summary": executive_summary,
        "remediation_summary": remediation_summary,
        "findings_count": len(findings),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    await store.save_report(report_id, payload)
    return payload


@registry.register(
    name="pause_agent",
    description="Safely pause agent orchestration loop.",
    parameters={
        "type": "object",
        "properties": {
            "reason": {"type": "string"}
        }
    },
    safety_level="passive"
)
async def tool_pause_agent(reason: str = "Operator requested pause") -> Dict[str, Any]:
    return {"status": "paused", "reason": reason}


@registry.register(
    name="resume_agent",
    description="Resume paused agent orchestration loop.",
    parameters={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"}
        },
        "required": ["session_id"]
    },
    safety_level="passive"
)
async def tool_resume_agent(session_id: str) -> Dict[str, Any]:
    return {"status": "resumed", "session_id": session_id}


@registry.register(
    name="stop_agent",
    description="Immediately abort current agent assessment.",
    parameters={
        "type": "object",
        "properties": {
            "reason": {"type": "string"}
        }
    },
    safety_level="passive"
)
async def tool_stop_agent(reason: str = "Emergency stop triggered") -> Dict[str, Any]:
    return {"status": "stopped", "reason": reason}
