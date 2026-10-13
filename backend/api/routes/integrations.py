"""Optional scanner integrations: Nuclei execution and CVE lookup."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import uuid
from datetime import datetime
from typing import Literal
from urllib.parse import urljoin

import aiohttp
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import db.store as store
from api.models import Finding, FindingStatus, Severity

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


class NucleiRunRequest(BaseModel):
    scan_id: str
    severity: list[Literal["info", "low", "medium", "high", "critical"]] = Field(default_factory=list)
    templates: list[str] = Field(default_factory=list, max_length=10)


class PushFindingRequest(BaseModel):
    destination: Literal["local", "slack", "github", "jira"] = "local"
    note: str = ""


from integrations.github import GitHubClient
from integrations.jira import JiraClient


@router.get("/status")
async def integration_status():
    nuclei_path = shutil.which("nuclei")
    gh = GitHubClient()
    jira = JiraClient()
    return {
        "nuclei": {
            "available": nuclei_path is not None,
            "path": nuclei_path or "",
            "fallback_available": True,
            "mode": "nuclei-binary" if nuclei_path else "centrix-builtin-templates",
        },
        "cve_lookup": {"available": True, "provider": "NVD"},
        "github": {"configured": gh.is_configured(), "repo": gh.repo or None},
        "jira": {"configured": jira.is_configured(), "project": jira.project_key or None},
        "slack": {"configured": bool(os.getenv("SLACK_WEBHOOK_URL"))},
    }


@router.get("/outbox")
async def list_outbox(finding_id: str | None = Query(default=None)):
    return await store.list_integration_outbox(finding_id)


@router.post("/findings/{finding_id}/push")
async def push_finding(finding_id: str, request: PushFindingRequest):
    finding = await store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await store.get_scan(finding.scan_id)
    item_id = f"OUT-{uuid.uuid4().hex[:8].upper()}"
    payload = {
        "id": item_id,
        "finding_id": finding_id,
        "destination": request.destination,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "title": finding.title,
        "severity": finding.severity.value,
        "target": finding.target,
        "note": request.note,
    }

    if request.destination == "slack":
        webhook = os.getenv("SLACK_WEBHOOK_URL")
        if webhook:
            async with aiohttp.ClientSession() as session:
                await session.post(webhook, json={"text": f"[Centrix] {finding.severity.value}: {finding.title} - {finding.target}"}, timeout=aiohttp.ClientTimeout(total=10))
            payload["status"] = "sent"
        else:
            payload["status"] = "queued-missing-webhook"
    elif request.destination == "github":
        gh_client = GitHubClient()
        res = await gh_client.create_issue(finding, scan)
        payload["status"] = res["status"]
        if res.get("issue_id"):
            payload["external_id"] = str(res["issue_id"])
        if res.get("html_url") or res.get("issue_url"):
            payload["external_url"] = res.get("html_url") or res.get("issue_url")
        if res.get("error"):
            payload["error"] = res["error"]
    elif request.destination == "jira":
        jira_client = JiraClient()
        res = await jira_client.create_issue(finding, scan)
        payload["status"] = res["status"]
        if res.get("issue_key"):
            payload["external_id"] = res["issue_key"]
        if res.get("issue_url"):
            payload["external_url"] = res["issue_url"]
        if res.get("error"):
            payload["error"] = res["error"]
    else:
        payload["status"] = "saved"

    await store.save_integration_outbox(item_id, finding_id, payload)
    await store.push_log(finding.scan_id, f"[INFO] Finding {finding_id} pushed to {request.destination}: {payload['status']}")
    return payload


@router.post("/nuclei/run")
async def run_nuclei(request: NucleiRunRequest):
    nuclei = shutil.which("nuclei")
    scan = await store.get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.config.authorized:
        raise HTTPException(status_code=403, detail="Scan is not authorised for target-touching integrations")
    if not nuclei:
        results = await _run_builtin_templates(scan.config.target, request.severity)
        for item in results[:200]:
            finding = _nuclei_to_finding(request.scan_id, item)
            await store.add_finding(request.scan_id, finding)
        await store.push_log(request.scan_id, f"[INFO] Centrix built-in templates imported {len(results[:200])} findings")
        return {"scan_id": request.scan_id, "imported": len(results[:200]), "results": results[:200], "engine": "centrix-builtin-templates"}

    args = [nuclei, "-u", scan.config.target, "-jsonl", "-silent", "-no-color"]
    if request.severity:
        args.extend(["-severity", ",".join(request.severity)])
    for template in request.templates:
        if any(token in template for token in ["..", "\x00"]):
            raise HTTPException(status_code=422, detail="Invalid template path")
        args.extend(["-t", template])

    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Nuclei run timed out") from exc

    if process.returncode not in {0, 1}:
        detail = stderr.decode("utf-8", errors="replace")[:600]
        raise HTTPException(status_code=502, detail=f"Nuclei failed: {detail}")

    parsed = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    for item in parsed[:200]:
        finding = _nuclei_to_finding(request.scan_id, item)
        await store.add_finding(request.scan_id, finding)

    await store.push_log(request.scan_id, f"[INFO] Nuclei integration imported {len(parsed[:200])} findings")
    return {"scan_id": request.scan_id, "imported": len(parsed[:200]), "results": parsed[:200], "engine": "nuclei-binary"}


@router.get("/cves/search")
async def search_cves(query: str = Query(..., min_length=2, max_length=120)):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": "10"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=20)) as response:
                if response.status >= 400:
                    raise HTTPException(status_code=502, detail=f"NVD lookup failed with HTTP {response.status}")
                payload = await response.json()
    except aiohttp.ClientError as exc:
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}") from exc

    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score = _best_cvss(metrics)
        descriptions = cve.get("descriptions", [])
        summary = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), "")
        results.append({
            "id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "score": score,
            "summary": summary,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
        })
    return {"query": query, "results": results}


def _nuclei_to_finding(scan_id: str, item: dict) -> Finding:
    info = item.get("info", {})
    severity = _severity(str(info.get("severity", "info")))
    target = str(item.get("matched-at") or item.get("host") or "")
    return Finding(
        id=f"NUC-{uuid.uuid4().hex[:8].upper()}",
        scan_id=scan_id,
        title=str(info.get("name") or item.get("template-id") or "Nuclei Finding"),
        severity=severity,
        category="Nuclei",
        target=target,
        parameter=str(item.get("template-id") or ""),
        confidence="Confirmed",
        status=FindingStatus.open,
        found_at=datetime.utcnow(),
        description=str(info.get("description") or "Imported from Nuclei JSONL output."),
        recommendation=str(info.get("remediation") or "Review the Nuclei template output and remediate the affected service."),
        evidence=json.dumps(item, indent=2)[:4000],
        cwe=None,
        cvss=None,
    )


BUILTIN_TEMPLATE_PATHS = [
    "/.env",
    "/.git/config",
    "/server-status",
    "/debug/vars",
    "/actuator/env",
    "/actuator",
    "/swagger-ui/",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
]


async def _run_builtin_templates(target: str, severities: list[str]) -> list[dict]:
    results: list[dict] = []
    severity_filter = {item.lower() for item in severities or []}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
        for path in BUILTIN_TEMPLATE_PATHS:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                async with session.get(url, ssl=False, allow_redirects=False) as response:
                    body = await response.text(errors="replace")
                    headers = dict(response.headers)
                    status = response.status
            except aiohttp.ClientError:
                continue
            item = _builtin_template_match(path, url, status, headers, body)
            if not item:
                continue
            severity = str((item.get("info") or {}).get("severity") or "info").lower()
            if severity_filter and severity not in severity_filter:
                continue
            results.append(item)
    return results


def _builtin_template_match(path: str, url: str, status: int, headers: dict[str, str], body: str) -> dict | None:
    if status not in {200, 203}:
        return None
    text = body or ""
    lowered = text.lower()
    checks = [
        {
            "path": "/.env",
            "markers": ("app_key=", "db_password", "aws_secret", "secret_key=", "database_url="),
            "id": "centrix-exposed-env",
            "name": "Exposed environment file",
            "severity": "high",
            "description": "An environment file appears to be publicly accessible and may expose secrets.",
            "remediation": "Remove public access to the environment file and rotate any exposed credentials.",
        },
        {
            "path": "/.git/config",
            "markers": ("[core]", "repositoryformatversion", "[remote"),
            "id": "centrix-exposed-git-config",
            "name": "Exposed Git configuration",
            "severity": "medium",
            "description": "A Git configuration file appears to be publicly accessible.",
            "remediation": "Block access to .git paths and remove deployed VCS metadata.",
        },
        {
            "path": "/server-status",
            "markers": ("apache server status", "server uptime", "total accesses"),
            "id": "centrix-apache-server-status",
            "name": "Exposed Apache server-status",
            "severity": "medium",
            "description": "Apache server-status appears to be publicly accessible.",
            "remediation": "Restrict server-status to trusted administrators only.",
        },
        {
            "path": "/debug/vars",
            "markers": ('"cmdline"', '"memstats"', '"goroutines"'),
            "id": "centrix-go-debug-vars",
            "name": "Exposed Go debug variables",
            "severity": "medium",
            "description": "Go expvar/debug output appears to be publicly accessible.",
            "remediation": "Disable debug endpoints or require authentication.",
        },
        {
            "path": "/actuator/env",
            "markers": ("propertysources", "systemenvironment", "spring"),
            "id": "centrix-actuator-env",
            "name": "Exposed Spring Actuator environment",
            "severity": "high",
            "description": "Spring Actuator environment output appears to be publicly accessible.",
            "remediation": "Restrict Actuator endpoints and avoid exposing environment details.",
        },
        {
            "path": "/actuator",
            "markers": ('"_links"', "actuator", "health"),
            "id": "centrix-actuator-index",
            "name": "Exposed Spring Actuator index",
            "severity": "low",
            "description": "Spring Actuator endpoint index appears to be publicly accessible.",
            "remediation": "Restrict Actuator endpoints to trusted networks or authenticated users.",
        },
        {
            "path": "/swagger-ui/",
            "markers": ("swagger ui", "openapi", "swagger-initializer"),
            "id": "centrix-swagger-ui",
            "name": "Exposed Swagger UI",
            "severity": "info",
            "description": "Swagger UI appears to be publicly accessible.",
            "remediation": "Ensure exposed API documentation is intentional and does not reveal sensitive operations.",
        },
        {
            "path": "/swagger.json",
            "markers": ('"swagger"', '"paths"', '"openapi"'),
            "id": "centrix-openapi-doc",
            "name": "Exposed API schema",
            "severity": "info",
            "description": "An API schema appears to be publicly accessible.",
            "remediation": "Confirm public API documentation is intentional and does not expose internal routes.",
        },
        {
            "path": "/openapi.json",
            "markers": ('"openapi"', '"paths"'),
            "id": "centrix-openapi-doc",
            "name": "Exposed API schema",
            "severity": "info",
            "description": "An API schema appears to be publicly accessible.",
            "remediation": "Confirm public API documentation is intentional and does not expose internal routes.",
        },
        {
            "path": "/api-docs",
            "markers": ('"swagger"', '"openapi"', '"paths"'),
            "id": "centrix-api-docs",
            "name": "Exposed API documentation",
            "severity": "info",
            "description": "API documentation appears to be publicly accessible.",
            "remediation": "Confirm public API documentation is intentional and does not expose internal routes.",
        },
        {
            "path": "/graphql",
            "markers": ("graphql", "graphiql", "apollo"),
            "id": "centrix-graphql-endpoint",
            "name": "Exposed GraphQL endpoint hint",
            "severity": "info",
            "description": "A GraphQL endpoint or console appears to be publicly reachable.",
            "remediation": "Disable GraphQL consoles in production and enforce authorization on resolvers.",
        },
    ]
    for check in checks:
        if path != check["path"]:
            continue
        markers = check["markers"]
        matched = [marker for marker in markers if marker in lowered]
        if not matched:
            return None
        return {
            "template-id": check["id"],
            "type": "centrix-builtin-template",
            "host": url,
            "matched-at": url,
            "curl-command": f"curl -i {url}",
            "matcher-name": ",".join(matched[:3]),
            "info": {
                "name": check["name"],
                "severity": check["severity"],
                "description": check["description"],
                "remediation": check["remediation"],
            },
            "status-code": status,
            "response-headers": headers,
            "extracted-results": [text[:600]],
        }
    return None


def _severity(value: str) -> Severity:
    return {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
        "info": Severity.info,
    }.get(value.lower(), Severity.info)


def _best_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData", {})
            score = data.get("baseScore")
            return float(score) if score is not None else None
    return None
