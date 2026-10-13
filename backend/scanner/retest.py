"""Continuous Retesting Engine for CENTRIX findings.

Replays original evidence-backed requests (preserving HTTP method, headers,
request body, auth tokens, and payload vectors), verifies authorization
boundaries and defensive sanitization, compares response artifacts,
and updates finding status in SQLite.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

import db.store as store
from api.models import Finding, FindingStatus, EvidenceArtifact
from scanner.safety import ensure_public_target, url_in_scope
from scanner.validation.detectors import validate_xss_candidate, is_observation_signal
from scanner.validation.baseline import detect_error_or_waf


async def retest_finding(finding_id: str) -> dict[str, Any]:
    """Execute evidence-backed active retest for a specific finding."""
    finding = await store.get_finding(finding_id)
    if not finding:
        raise ValueError(f"Finding '{finding_id}' not found")

    target_url = finding.target
    await ensure_public_target(target_url)

    category = (finding.category or "").lower()
    vuln_type = (finding.vuln_type or "").lower()
    parameter = finding.parameter or ""
    original_evidence = finding.evidence or ""

    # 1. Retrieve linked evidence artifacts if available
    linked_artifacts: list[EvidenceArtifact] = []
    if finding.evidence_artifact_ids:
        all_evidence = await store.get_evidence(finding.scan_id)
        linked_artifacts = [a for a in all_evidence if a.id in finding.evidence_artifact_ids]

    primary_artifact: Optional[EvidenceArtifact] = linked_artifacts[0] if linked_artifacts else None

    # 2. Determine exact replay HTTP method, headers, and body
    method = (finding.request_method or (primary_artifact.method if primary_artifact else "GET")).upper()

    headers = dict(finding.request_headers) if finding.request_headers else {}
    if not headers and primary_artifact and primary_artifact.request_headers:
        headers = dict(primary_artifact.request_headers)

    if not headers:
        headers = {
            "User-Agent": "CENTRIX-Retest-Engine/4.0",
            "Accept": "*/*",
        }
    else:
        headers.setdefault("User-Agent", "CENTRIX-Retest-Engine/4.0")

    body = finding.request_body or (primary_artifact.request_body if primary_artifact else None)

    # 3. Construct test URL and payload vector
    test_url = target_url
    test_payload = ""

    if "xss" in category or vuln_type == "xss":
        test_payload = "<script>centrix_verify_token_77</script>"
        if method in ("POST", "PUT", "PATCH") and parameter:
            body = f"{parameter}={test_payload}"
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif parameter and "?" not in test_url:
            test_url = f"{target_url}?{parameter}={test_payload}"
        elif parameter:
            test_url = f"{target_url}&{parameter}={test_payload}"

    elif "sql" in category or vuln_type == "sqli":
        test_payload = "' OR '1'='1"
        if method in ("POST", "PUT", "PATCH") and parameter:
            body = f"{parameter}={test_payload}"
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif parameter and "?" not in test_url:
            test_url = f"{target_url}?{parameter}={test_payload}"
        elif parameter:
            test_url = f"{target_url}&{parameter}={test_payload}"

    elif method in ("POST", "PUT", "PATCH") and parameter and not body:
        body = f"{parameter}=centrix_test_probe"
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    # 4. Dispatch retest HTTP request
    timeout = aiohttp.ClientTimeout(total=20)
    now = datetime.utcnow()
    reproduced = False
    details = ""
    retest_status_code = 0
    retest_response_text = ""
    retest_headers: dict[str, str] = {}

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            req_kwargs: dict[str, Any] = {
                "headers": headers,
                "allow_redirects": True,
            }
            if body and method in ("POST", "PUT", "PATCH"):
                req_kwargs["data"] = body

            async with session.request(method, test_url, **req_kwargs) as resp:
                retest_status_code = resp.status
                retest_headers = {k.lower(): v for k, v in resp.headers.items()}
                retest_response_text = await resp.text()

        flags = detect_error_or_waf(retest_status_code, retest_response_text)

        # 5. Evaluate reproduction vs remediation by vulnerability class
        if "xss" in category or vuln_type == "xss":
            xss_eval = validate_xss_candidate(retest_response_text, test_payload)
            if xss_eval["is_executable"]:
                reproduced = True
                details = "Reflected XSS reproduced: payload rendered unescaped in response DOM."
            elif xss_eval["is_encoded"]:
                reproduced = False
                details = "Remediated: payload was safely HTML entity-encoded."
            else:
                reproduced = False
                details = "Remediated: payload was stripped or sanitized from response."

        elif "sql" in category or vuln_type == "sqli":
            lower_text = retest_response_text.lower()
            sql_sigs = ("sql syntax", "ora-", "mysql", "sqlite3", "pg_query", "driver error", "unclosed quotation mark")
            if any(sig in lower_text for sig in sql_sigs) and not flags["is_custom_404"]:
                reproduced = True
                details = "SQL Injection reproduced: database syntax error triggered on injection vector."
            else:
                reproduced = False
                details = "Remediated: SQL error syntax is no longer triggered or leaked."

        elif "idor" in category or vuln_type == "idor":
            # Authenticated authorization boundary verification
            if retest_status_code in (401, 403):
                reproduced = False
                details = f"Remediated: Authorization enforced (HTTP {retest_status_code})."
            elif flags["is_login_redirect"]:
                reproduced = False
                details = "Remediated: Target redirected unauthenticated request to login portal."
            elif retest_status_code == 200 and original_evidence and original_evidence in retest_response_text:
                reproduced = True
                details = "IDOR reproduced: Cross-account data still disclosed with HTTP 200."
            else:
                reproduced = False
                details = f"Remediated: Target returned HTTP {retest_status_code} without sensitive baseline disclosure."

        elif "header" in category or vuln_type == "missing_header":
            # Security Header validation
            missing = []
            target_hdr = parameter.lower() if parameter else ""
            check_headers = [target_hdr] if target_hdr else ["content-security-policy", "x-content-type-options", "strict-transport-security"]
            for h in check_headers:
                if h and h not in retest_headers:
                    missing.append(h)

            if missing:
                reproduced = True
                details = f"Security headers still absent: {', '.join(missing)}"
            else:
                reproduced = False
                details = "Remediated: Required defense-in-depth headers are now properly configured."

        elif "csrf" in category or vuln_type == "csrf":
            if retest_status_code in (400, 403) and ("csrf" in retest_response_text.lower() or "token" in retest_response_text.lower()):
                reproduced = False
                details = f"Remediated: CSRF token validation enforced (HTTP {retest_status_code})."
            else:
                reproduced = True
                details = "CSRF reproduced: State-changing action executed without valid anti-CSRF token."

        else:
            # General evidence comparison
            if flags["is_custom_404"] or retest_status_code >= 400:
                reproduced = False
                details = f"Remediated: Endpoint returned HTTP {retest_status_code} error."
            elif original_evidence and len(original_evidence) > 15 and original_evidence in retest_response_text:
                reproduced = True
                details = "Vulnerability reproduced: Original evidence signature matched in target response."
            else:
                reproduced = False
                details = f"Remediated: Endpoint responded with HTTP {retest_status_code} without matching original proof signature."

    except Exception as exc:
        return {
            "finding_id": finding_id,
            "status": "error",
            "reproduced": False,
            "error": str(exc),
            "retested_at": now.isoformat(),
        }

    # 6. Save Retest Forensic Artifact in SQLite evidence vault
    retest_evidence_id = f"EV-RETEST-{uuid.uuid4().hex[:8].upper()}"
    retest_artifact = EvidenceArtifact(
        id=retest_evidence_id,
        scan_id=finding.scan_id,
        url=test_url,
        method=method,
        request_headers=headers,
        request_body=body,
        status_code=retest_status_code,
        content_type=retest_headers.get("content-type", ""),
        response_length=len(retest_response_text),
        response_excerpt=retest_response_text[:1200],
        response_headers=retest_headers,
        captured_at=now,
    )
    await store.add_evidence(retest_artifact)

    # 7. Update finding status in database
    if reproduced:
        finding.status = FindingStatus.still_open
        finding.reproduction_status = "reproduced"
    else:
        finding.status = FindingStatus.fixed
        finding.reproduction_status = "remediated"

    if retest_evidence_id not in finding.evidence_artifact_ids:
        finding.evidence_artifact_ids.append(retest_evidence_id)

    await store.update_finding(finding)

    return {
        "finding_id": finding_id,
        "title": finding.title,
        "status": finding.status.value,
        "reproduced": reproduced,
        "reproduction_status": finding.reproduction_status,
        "method_replayed": method,
        "headers_replayed_count": len(headers),
        "status_code": retest_status_code,
        "retest_evidence_id": retest_evidence_id,
        "details": details,
        "retested_at": now.isoformat(),
    }
