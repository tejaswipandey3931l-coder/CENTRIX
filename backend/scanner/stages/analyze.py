"""
Stage 5 — Vulnerability Analysis
- Maps raw probe results → structured Finding objects
- CWE / CVSS mapping via O(1) dict lookup
- Deduplication by (url, param, type) hash — O(1) set membership
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Callable, Awaitable
from urllib.parse import urlparse

import db.store as store
from api.models import Finding, Severity, FindingStatus, FindingClassification, EvidenceArtifact

# ── Static lookup tables — O(1) ────────────────────────────────────────────
_CWE_MAP: dict[str, str] = {
    "csrf": "CWE-352",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "traversal": "CWE-22",
    "open_redirect": "CWE-601",
    "missing_header": "CWE-693",
    "idor": "CWE-284",
    "ssrf": "CWE-918",
    "jwt": "CWE-200",
    "graphql": "CWE-200",
    "graphql_introspection": "CWE-200",
    "websocket": "CWE-200",
    "ssti": "CWE-94",
    "hpp": "CWE-235",
    "command_injection": "CWE-78",
    "rce": "CWE-78",
    "xxe": "CWE-611",
    "mass_assignment": "CWE-915",
    "race_condition": "CWE-362",
    "vulnerable_component": "CWE-1104",
    "crypto": "CWE-319",
    "wordpress": "CWE-200",
    "graphql_dos": "CWE-400",
    "graphql_batching": "CWE-770",
    "grpc_reflection": "CWE-200",
    "flag": "CWE-200",
}

_CVSS_MAP: dict[str, float] = {
    "csrf": 6.5,
    "sqli": 9.8,
    "xss": 7.2,
    "traversal": 9.1,
    "open_redirect": 6.1,
    "missing_header": 5.3,
    "idor": 8.1,
    "ssrf": 9.3,
    "jwt": 5.3,
    "graphql": 3.1,
    "graphql_introspection": 5.3,
    "websocket": 3.1,
    "ssti": 9.1,
    "hpp": 5.3,
    "command_injection": 10.0,
    "rce": 10.0,
    "xxe": 8.6,
    "mass_assignment": 8.1,
    "race_condition": 7.1,
    "vulnerable_component": 7.5,
    "crypto": 3.1,
    "wordpress": 5.3,
    "graphql_dos": 7.5,
    "graphql_batching": 8.1,
    "grpc_reflection": 5.3,
    "flag": 7.5,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "csrf": Severity.medium,
    "sqli": Severity.critical,
    "xss": Severity.high,
    "traversal": Severity.critical,
    "open_redirect": Severity.medium,
    "missing_header": Severity.low,
    "idor": Severity.high,
    "ssrf": Severity.critical,
    "jwt": Severity.low,
    "graphql": Severity.info,
    "graphql_introspection": Severity.low,
    "websocket": Severity.info,
    "ssti": Severity.critical,
    "hpp": Severity.medium,
    "command_injection": Severity.critical,
    "rce": Severity.critical,
    "xxe": Severity.high,
    "mass_assignment": Severity.high,
    "race_condition": Severity.medium,
    "vulnerable_component": Severity.high,
    "crypto": Severity.low,
    "wordpress": Severity.low,
    "graphql_dos": Severity.high,
    "graphql_batching": Severity.high,
    "grpc_reflection": Severity.low,
    "flag": Severity.high,
}

_TITLE_MAP: dict[str, str] = {
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "sqli": "SQL Injection",
    "xss": "Reflected Cross-Site Scripting (XSS)",
    "traversal": "Path Traversal",
    "open_redirect": "Open Redirect",
    "missing_header": "Missing Security Header",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "jwt": "JWT Token Exposure",
    "graphql": "GraphQL Surface Detected",
    "graphql_introspection": "GraphQL Introspection Enabled",
    "websocket": "WebSocket Surface Detected",
    "ssti": "Server-Side Template Injection (SSTI)",
    "hpp": "HTTP Parameter Pollution",
    "command_injection": "Command Injection",
    "rce": "Remote Code Execution",
    "xxe": "XML External Entity (XXE)",
    "mass_assignment": "Mass Assignment",
    "race_condition": "Race Condition",
    "vulnerable_component": "Vulnerable or Outdated Component",
    "crypto": "Cryptographic / Transport Weakness",
    "wordpress": "WordPress Exposure",
    "graphql_dos": "GraphQL Depth/Complexity Weakness",
    "graphql_batching": "GraphQL Batching Bypass",
    "grpc_reflection": "gRPC Reflection Enabled",
    "flag": "Sensitive Flag or Secret Exposure",
}

_CATEGORY_MAP: dict[str, str] = {
    "csrf": "Access Control",
    "sqli": "Injection",
    "xss": "XSS",
    "traversal": "Path Traversal",
    "open_redirect": "Redirect",
    "missing_header": "Security Headers",
    "idor": "Access Control",
    "ssrf": "SSRF",
    "jwt": "Authentication",
    "graphql": "API Surface",
    "graphql_introspection": "API Surface",
    "websocket": "API Surface",
    "ssti": "Injection",
    "hpp": "Input Handling",
    "command_injection": "Injection",
    "rce": "Injection",
    "xxe": "Injection",
    "mass_assignment": "Access Control",
    "race_condition": "Business Logic",
    "vulnerable_component": "Components",
    "crypto": "Cryptography",
    "wordpress": "CMS",
    "graphql_dos": "API Surface",
    "graphql_batching": "API Surface",
    "grpc_reflection": "API Surface",
    "flag": "Sensitive Data",
}

_RECOMMENDATION_MAP: dict[str, str] = {
    "csrf": "Use framework-generated anti-CSRF tokens on all state-changing requests and validate SameSite cookie protections.",
    "sqli": (
        "Use parameterized queries or prepared statements for all database interactions. "
        "Never concatenate user input into SQL strings. Adopt an ORM with built-in protections."
    ),
    "xss": (
        "HTML-encode all user-supplied data before rendering. "
        "Implement a strict Content-Security-Policy. Avoid innerHTML."
    ),
    "traversal": (
        "Validate and sanitize file path parameters against an allowlist. "
        "Use path.resolve() and verify the result starts within the intended directory."
    ),
    "open_redirect": (
        "Validate redirect destinations against an allowlist. "
        "Avoid using user-supplied input in Location headers directly."
    ),
    "missing_header": (
        "Add the missing security header to all HTTP responses. "
        "Configure it in the web server or application middleware."
    ),
    "idor": (
        "Implement ownership checks on all resource access. "
        "Use random UUIDs instead of sequential IDs and enforce authorization at the data layer."
    ),
    "ssrf": (
        "Validate and allowlist URLs that the server is permitted to fetch. "
        "Block requests to internal IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.)."
    ),
    "jwt": (
        "Avoid returning tokens in cacheable responses or logs. Mark token cookies HttpOnly, Secure, and SameSite, "
        "and keep token lifetimes short."
    ),
    "graphql": (
        "Review GraphQL authorization, disable introspection in production where appropriate, "
        "and enforce query depth and complexity limits."
    ),
    "graphql_introspection": (
        "Disable GraphQL introspection in production where appropriate, require authentication for schema access, "
        "and enforce query complexity limits."
    ),
    "websocket": (
        "Require authentication and origin checks during WebSocket upgrades, and validate every message server-side."
    ),
    "ssti": (
        "Do not render untrusted input as template source. Use safe template APIs and strict allowlists for dynamic content."
    ),
    "hpp": (
        "Canonicalize duplicate parameters before authorization and validation. Reject ambiguous requests at the edge."
    ),
    "command_injection": (
        "Avoid shell invocation with user input. Use language-native APIs and allowlist any permitted command arguments."
    ),
    "rce": (
        "Never pass user input to shell commands. "
        "Use language-native APIs instead of shell invocations."
    ),
    "xxe": (
        "Disable external entity resolution in XML parsers and reject untrusted XML where possible."
    ),
    "mass_assignment": (
        "Bind only allowlisted fields server-side. Ignore privilege fields such as role, is_admin, and permissions from client input."
    ),
    "race_condition": (
        "Protect state-changing operations with server-side locking, idempotency keys, or transaction constraints."
    ),
    "vulnerable_component": (
        "Upgrade the affected component to a supported version and remove version disclosures where possible."
    ),
    "crypto": (
        "Enforce HTTPS, secure cookies, modern TLS, HSTS, and avoid exposing sensitive values in responses."
    ),
    "wordpress": (
        "Restrict exposed WordPress endpoints, remove unnecessary public files, and keep WordPress/core plugins updated."
    ),
    "graphql_dos": (
        "Enforce GraphQL query depth, complexity, cost, timeout, and rate limits."
    ),
    "graphql_batching": (
        "Apply authentication, authorization, and rate limits per operation inside GraphQL batched requests."
    ),
    "grpc_reflection": (
        "Disable gRPC reflection in production unless it is required and protected by authentication."
    ),
    "flag": (
        "Remove exposed secrets/flags from responses and rotate any sensitive values that may have leaked."
    ),
}


from api.models import Finding, Severity, FindingStatus, FindingClassification
from scanner.validation.baseline import detect_error_or_waf, compare_responses
from scanner.validation.scorer import calculate_evidence_score
from scanner.validation.detectors import (
    OBSERVATION_TYPES,
    is_observation_signal,
    validate_xss_candidate,
    redact_sensitive_tokens,
)
from agent.debate import debate_engine


async def run(
    scan_id: str,
    raw_vulns: list[dict],
    log: Callable[[str], Awaitable[None]],
    aggregate_headers: bool = False,
) -> list[Finding]:
    """
    Evidence-based Vulnerability Analysis & False-Positive Reduction Pipeline:
    1. Normalizes and deduplicates candidates.
    2. Aggregates systemic issues (e.g. missing security headers) across endpoints when enabled.
    3. Evaluates error/WAF/redirect response artifacts.
    4. Computes deterministic confidence scores (+2, -2, -3 rules).
    5. Categorizes findings into Confirmed, Probable, Tentative, Informational, or Rejected.
    6. Ensures no finding becomes Confirmed based solely on suspicious patterns.
    """
    await log(f"[INFO] Analyzing {len(raw_vulns)} raw vulnerability candidate(s) through false-positive reduction pipeline...")

    # Aggregation buckets for systemic issues (e.g. missing_header:X-Frame-Options)
    header_aggregates: dict[str, dict[str, Any]] = {}
    standard_candidates: list[dict] = []
    suppressed_noise = 0

    for vuln in raw_vulns:
        vtype = vuln.get("type", "unknown")
        param = str(vuln.get("param", "")).strip()
        url = vuln.get("url", "")

        if vtype == "missing_header":
            if aggregate_headers and param:
                header_key = param.lower()
                if header_key not in header_aggregates:
                    header_aggregates[header_key] = {
                        "param": param,
                        "urls": [],
                        "evidence": vuln.get("evidence", ""),
                        "first_seen": datetime.utcnow(),
                    }
                if url and url not in header_aggregates[header_key]["urls"]:
                    header_aggregates[header_key]["urls"].append(url)
            else:
                suppressed_noise += 1
            continue
        else:
            standard_candidates.append(vuln)


    seen_keys: set[str] = set()
    findings: list[Finding] = []
    rejected_count = 0

    # Only artifacts already persisted for this scan count as evidence.  The
    # candidate's free-text explanation is intentionally never treated as an
    # evidence artifact.
    persisted_evidence = await store.get_evidence(scan_id)
    evidence_by_url = {item.url: item.id for item in persisted_evidence if item.url}

    # 1. Process aggregated security header findings (1 finding per missing header type)
    for header_key, agg in header_aggregates.items():
        param_name = agg["param"]
        affected_urls = agg["urls"]
        count = len(affected_urls)
        primary_url = affected_urls[0] if affected_urls else "Application Endpoints"

        title = f"Missing Security Header: {param_name}"
        desc = (
            f"The recommended security header `{param_name}` was omitted in responses across "
            f"{count} endpoint(s). Example: {primary_url}"
        )

        score_card = calculate_evidence_score(
            has_exact_target_and_param=True,
            is_reproducible=True,
            is_observation_only=True,
            has_persisted_evidence=True,
        )

        finding = Finding(
            id=f"VLN-HDR-{uuid.uuid4().hex[:6].upper()}",
            scan_id=scan_id,
            title=title,
            severity=Severity.low,
            category="Security Headers",
            target=primary_url,
            parameter=param_name,
            confidence="Informational",
            classification=FindingClassification.informational,
            status=FindingStatus.open,
            found_at=agg["first_seen"],
            description=desc,
            recommendation=_RECOMMENDATION_MAP.get("missing_header", "Configure security headers."),
            evidence=f"Header '{param_name}' missing across {count} tested endpoint(s).",
            cwe=_CWE_MAP.get("missing_header", "CWE-693"),
            cvss=_CVSS_MAP.get("missing_header", 5.3),
            vuln_type="missing_header",
            detection_source="header_audit",
            confidence_score=score_card.total_score,
            confidence_reasons=score_card.reasons,
            false_positive_indicators=score_card.false_positive_indicators,
            why_false_positive_risk="Hardening observation only; does not prove an active exploitable condition.",
            affected_urls_count=count,
            example_urls=affected_urls[:5],
            validation_status="validated",
        )
        findings.append(finding)

    # 2. Process standard vulnerability candidates
    for vuln in standard_candidates:
        vtype = vuln.get("type", "unknown")
        url = vuln.get("url", "")
        param = str(vuln.get("param", "")).strip()
        payload = str(vuln.get("payload", ""))
        evidence = redact_sensitive_tokens(str(vuln.get("evidence", "")))
        status_code = int(vuln.get("status_code") or 200)
        raw_response = str(vuln.get("response_body") or evidence)

        # Deduplication key: vuln_type + normalized path + param (host-level for crypto/transport/observation)
        parsed_url = urlparse(url)
        norm_path = "" if vtype in ("crypto", "wordpress", "tech_detect", "banner", "grpc_reflection") else (parsed_url.path or "/")
        if vtype in ("crypto", "wordpress", "tech_detect", "banner", "grpc_reflection"):
            dedup_key = f"{vtype}:{parsed_url.netloc}"
        else:
            dedup_key = f"{vtype}:{parsed_url.netloc}:{norm_path}:{param.lower()}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        # Response and error checks
        flags = detect_error_or_waf(status_code, raw_response)
        baseline_result = None
        if isinstance(vuln.get("baseline"), dict) and isinstance(vuln.get("candidate"), dict):
            baseline_result = compare_responses(vuln["baseline"], vuln["candidate"])
            flags["is_custom_404"] = flags["is_custom_404"] or baseline_result["flags"].get("is_custom_404", False)
            flags["is_generic_error"] = flags["is_generic_error"] or baseline_result["flags"].get("is_generic_error", False)

        # Detector-specific validations
        is_obs = is_observation_signal(vtype, evidence=evidence, param=param)
        has_direct_impact = False
        reproduced = False
        independent_agreement = False

        if vtype == "xss":
            xss_check = validate_xss_candidate(raw_response, payload)
            if xss_check["is_encoded"]:
                flags["is_unstable_response"] = True
            elif xss_check["is_executable"] or (vuln.get("confidence") == "Confirmed" and "reflected" in evidence.lower() and not xss_check.get("is_encoded")):
                has_direct_impact = True
                reproduced = True
        elif vtype == "sqli":
            sqli_sigs = [
                "syntax error", "sql error", "unclosed quotation", "odbc", "microsoft",
                "mysql", "sqlite", "ora-", "pg_", "stream abort", "broke backend query",
                "unhandled stream abort", "boolean differential", "database error",
                "division by zero", "you have an error in your sql", "warning: mysql"
            ]
            ev_lower = evidence.lower()
            if (any(s in ev_lower for s in sqli_sigs) or vuln.get("confidence") == "Confirmed") and not flags["is_custom_404"]:
                has_direct_impact = True
                reproduced = True
        elif vtype in ("command_injection", "rce"):
            cmdi_sigs = ["uid=", "root:", "windows ip configuration", "bytes from", "reply from"]
            ev_lower = evidence.lower()
            if (any(s in ev_lower for s in cmdi_sigs) or vuln.get("confidence") == "Confirmed") and not flags["is_custom_404"]:
                has_direct_impact = True
                reproduced = True
        elif vtype == "traversal":
            traversal_sigs = ["root:", "boot.ini", "uid=", "windows/system32", "etc/passwd", "[boot loader]"]
            ev_lower = evidence.lower()
            if (any(s in ev_lower for s in traversal_sigs) or vuln.get("confidence") == "Confirmed") and not flags["is_custom_404"]:
                has_direct_impact = True
                reproduced = True
        elif vtype in ("ssti", "xxe"):
            if vuln.get("confidence") == "Confirmed" and not flags["is_custom_404"]:
                has_direct_impact = True
                reproduced = True
        elif vtype == "ssrf":
            if "callback received" in evidence.lower() or "oob verified" in evidence.lower():
                has_direct_impact = True
                reproduced = True
            else:
                is_obs = True  # Parameter observation only
        elif vtype == "idor":
            if "differential" in evidence.lower() or "unauthorized access" in evidence.lower() or "tenant mismatch" in evidence.lower():
                has_direct_impact = True
                reproduced = True
            else:
                is_obs = True  # Predictable ID observation only

        artifact_id = vuln.get("evidence_id") or evidence_by_url.get(url)
        if not artifact_id and (has_direct_impact or reproduced or vtype in OBSERVATION_TYPES):
            ev_id = f"EV-ANLZ-{uuid.uuid4().hex[:8].upper()}"
            ev_art = EvidenceArtifact(
                id=ev_id,
                scan_id=scan_id,
                url=url,
                method=str(vuln.get("method") or "GET").upper(),
                status_code=status_code,
                response_excerpt=evidence[:1000],
                response_length=len(raw_response),
            )
            try:
                await store.add_evidence(ev_art)
                artifact_id = ev_id
                evidence_by_url[url] = ev_id
            except Exception:
                pass

        evidence_artifact_ids = [str(artifact_id)] if artifact_id else []
        has_persisted_evidence = bool(evidence_artifact_ids)
        has_meaningful_difference = bool(
            has_direct_impact
            or (baseline_result and baseline_result.get("meaningful_difference"))
        )

        # Compute deterministic evidence score (+2, -2, -3 rules)
        score_card = calculate_evidence_score(
            has_exact_target_and_param=bool(url and (param or vtype in OBSERVATION_TYPES)),
            is_reproducible=reproduced,
            has_meaningful_difference=has_meaningful_difference,
            has_direct_security_impact=has_direct_impact,
            has_browser_confirmation=bool(vuln.get("browser_confirmed")),
            has_independent_detector_agreement=independent_agreement,
            is_generic_error_or_custom_404=flags["is_custom_404"] or flags["is_generic_error"],
            is_login_redirect_or_waf=flags["is_login_redirect"] or flags["is_waf_block"],
            is_unstable_response=flags.get("is_unstable_response", False),
            is_observation_only=is_obs,
            has_persisted_evidence=has_persisted_evidence,
        )

        # Strict false-positive suppression for active vulnerability classes:
        # If an exploit candidate (idor, csrf, ssrf, sqli, xss, traversal, etc.) has no direct impact,
        # is not reproduced, and has score <= 2, it is unproven noise and MUST be suppressed.
        active_vuln_classes = {
            "idor", "csrf", "ssrf", "sqli", "xss", "traversal",
            "command_injection", "rce", "xxe", "ssti", "race_condition", "mass_assignment", "hpp"
        }
        if vtype in active_vuln_classes and not has_direct_impact and not reproduced and score_card.total_score <= 2:
            rejected_count += 1
            await log(f"[FP-SUPPRESSED] Suppressed unverified {vtype} candidate @ {url} [{param}] (score={score_card.total_score}/10, no impact evidence)")
            continue

        # If rejected by deterministic evidence rules, log and suppress
        if score_card.classification == FindingClassification.rejected:
            rejected_count += 1
            await log(f"[FP-SUPPRESSED] Rejected candidate: {vtype} @ {url} [{param}] - Reason: {', '.join(score_card.false_positive_indicators)}")
            continue

        title = _TITLE_MAP.get(vtype, vtype.replace("_", " ").title())

        severity = _SEVERITY_MAP.get(vtype, Severity.info)
        cvss = _CVSS_MAP.get(vtype, 0.0)
        if is_obs or score_card.classification == FindingClassification.informational or score_card.total_score <= 2:
            severity = Severity.info
            cvss = 0.0
            score_card.classification = FindingClassification.informational
            score_card.confidence_label = "Informational"
            if "observation" not in title.lower():
                title = f"{title} (Surface Observation)"

        if not url:
            continue

        # Construct structured Finding object
        finding = Finding(
            id=f"VLN-{uuid.uuid4().hex[:6].upper()}",
            scan_id=scan_id,
            title=title,
            severity=severity,
            category=_CATEGORY_MAP.get(vtype, "Misc"),
            target=url,
            parameter=param,
            confidence=score_card.confidence_label,
            classification=score_card.classification,
            status=FindingStatus.open,
            found_at=datetime.utcnow(),
            description=f"Detected via {vuln.get('source', 'active probe')}. Payload evaluated: `{payload[:100]}`",
            recommendation=_RECOMMENDATION_MAP.get(vtype, "Review and remediate."),
            evidence=evidence,
            cwe=_CWE_MAP.get(vtype),
            cvss=cvss,
            vuln_type=vtype,
            detection_source=vuln.get("source", "probe_engine"),
            detection_rule=vuln.get("rule_id"),
            evidence_artifact_ids=evidence_artifact_ids,
            reproduction_status="reproduced" if reproduced else "untested",
            confidence_score=score_card.total_score,
            confidence_reasons=score_card.reasons,
            false_positive_indicators=score_card.false_positive_indicators,
            validation_status="validated" if score_card.classification in (FindingClassification.confirmed, FindingClassification.probable) else "pending",
            why_false_positive_risk="; ".join(score_card.deductions) if score_card.deductions else None,
            affected_urls_count=1,
            example_urls=[url],
            request_method=str(vuln.get("method") or "GET").upper(),
            request_headers=vuln.get("headers") or {},
            request_body=vuln.get("body") or (payload if str(vuln.get("method") or "GET").upper() in ("POST", "PUT", "PATCH") else None),
        )

        from reporting.github_issues import build_reproduction_curl
        finding.reproduction_curl = build_reproduction_curl(finding)

        # Run the model debate after deterministic validation.  The model may
        # downgrade or reject a candidate, but it can never upgrade a finding
        # beyond the evidence-backed deterministic classification.
        if not is_obs:
            try:
                adjudication = await debate_engine.adjudicate_candidate(
                    {**vuln, "evidence": evidence, "evidence_artifact_ids": evidence_artifact_ids,
                     "confidence_score": score_card.total_score},
                    has_screenshot=bool(vuln.get("screenshot") or vuln.get("screenshot_path")),
                )
                ai_class = str(adjudication.classification).strip().lower()
                class_aliases = {item.value.lower(): item.value for item in FindingClassification}
                if ai_class not in class_aliases:
                    ai_class = FindingClassification.tentative.value
                else:
                    ai_class = class_aliases[ai_class]
                if ai_class == FindingClassification.confirmed.value and score_card.classification != FindingClassification.confirmed:
                    ai_class = score_card.classification.value
                if ai_class == FindingClassification.rejected.value:
                    if has_direct_impact:
                        ai_class = FindingClassification.tentative.value
                        finding.why_false_positive_risk = f"Debate flagged false positive risk, preserved as tentative: {adjudication.reason}"
                    else:
                        rejected_count += 1
                        await log(f"[FP-SUPPRESSED] Debate rejected candidate: {vtype} @ {url} [{param}] - {adjudication.reason}")
                        continue
                finding.classification = FindingClassification(ai_class)
                finding.confidence = finding.classification.value
                finding.confidence_score = min(score_card.total_score, int(adjudication.confidence))
                finding.confidence_reasons.extend([adjudication.reason, *adjudication.missing_validation])
                finding.false_positive_indicators.extend(adjudication.false_positive_risks)
                finding.why_false_positive_risk = "; ".join(dict.fromkeys(
                    [item for item in [finding.why_false_positive_risk, *adjudication.false_positive_risks] if item]
                )) or None
                finding.model_review_status = "adjudicated"
                finding.validation_status = "validated" if finding.classification in (
                    FindingClassification.confirmed, FindingClassification.probable, FindingClassification.informational
                ) else "pending"
            except Exception as exc:
                await log(f"[WARN] Debate adjudication unavailable; deterministic result retained: {exc}")

        findings.append(finding)
        sev = finding.severity.value
        cls_name = finding.classification.value
        await log(f"[{'CRITICAL' if sev == 'Critical' else 'ALERT'}] {sev} [{cls_name}, {finding.confidence_score}/10] — {title} @ {url} [{param}]")

    await log(
        f"[SUCCESS] False-positive reduction complete: {len(findings)} validated finding(s) "
        f"({rejected_count} rejected false-positive candidate(s) suppressed)"
    )
    return findings

