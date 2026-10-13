"""Low-noise passive checks adapted from Wraith's captured-traffic scanner."""
from __future__ import annotations
import re
from typing import Callable, Awaitable
from urllib.parse import parse_qsl, urlparse, urljoin

REQUIRED_HEADERS = {"content-security-policy": "Content-Security-Policy", "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options"}
CSRF_NAMES = {"csrf", "csrf_token", "xsrf", "xsrf_token", "authenticity_token", "_token"}
STATE_CHANGING_NAMES = {"password", "password_new", "password_conf", "email", "change", "delete", "update", "transfer", "amount", "role", "admin"}
IDOR_PARAMETERS = {"id", "user", "userid", "user_id", "account", "account_id", "customer", "customer_id", "order", "order_id", "invoice", "invoice_id", "file", "file_id", "document", "document_id"}
SSRF_PARAMETERS = {"url", "uri", "target", "endpoint", "callback", "callback_url", "webhook", "webhook_url", "feed", "image_url", "file_url", "fetch", "proxy"}
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}")
WEBSOCKET_PATTERN = re.compile(r"\bwss?://[^\s\"'<>)]+", re.IGNORECASE)

async def run(evidence: list[dict], log: Callable[[str], Awaitable[None]]) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    missing_headers: dict[str, dict] = {}
    for item in evidence:
        headers = {key.lower(): value for key, value in item.get("response_headers", {}).items()}
        url = item["url"]
        parsed = urlparse(url)
        excerpt = str(item.get("response_excerpt", ""))
        content_type = str(item.get("content_type", "")).lower()

        for key, display in REQUIRED_HEADERS.items():
            if key not in headers:
                _count_missing_header(missing_headers, key, display, url)
        if url.startswith("https://") and "strict-transport-security" not in headers:
            _count_missing_header(missing_headers, "strict-transport-security", "Strict-Transport-Security", url)
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
            findings.append({"type":"missing_header", "url":url, "param":"CORS policy", "payload":"", "evidence":"Credentialed wildcard CORS response", "confidence":"Confirmed"})
        findings.extend(_parameter_surface_findings(url, parsed.query, seen))
        findings.extend(_jwt_findings(url, headers, excerpt, seen))
        findings.extend(_graphql_findings(url, content_type, excerpt, seen))
        findings.extend(_websocket_findings(url, headers, excerpt, seen))
        for form in item.get("forms", []):
            method = str(form.get("method", "GET")).upper()
            action_url = urljoin(url, form.get("action") or url)
            action_lower = action_url.lower()
            names = {str(name).lower() for name in form.get("inputs", [])}
            is_static_page = any(static_ext in action_lower for static_ext in ["/about", "/default", "/index", "/contact", "/home", "/view", "/display"]) and not any(kw in action_lower for kw in ["update", "delete", "create", "edit", "submit", "change", "post"])
            looks_state_changing = (method in {"POST", "PUT", "PATCH", "DELETE"} or bool(names.intersection(STATE_CHANGING_NAMES))) and not is_static_page
            if looks_state_changing and not names.intersection(CSRF_NAMES):
                findings.append({"type":"csrf", "url": action_url, "param":"form", "payload":"", "evidence":f"State-changing {method} form has no recognizable anti-CSRF token", "confidence":"Tentative"})
    if missing_headers:
        observed = ", ".join(item["param"] for item in missing_headers.values())
        await log(f"[INFO] Missing security headers observed as telemetry only: {observed}")
    await log(f"[INFO] Passive evidence analysis produced {len(findings)} candidates")
    return findings


def _count_missing_header(bucket: dict[str, dict], key: str, display: str, url: str) -> None:
    item = bucket.setdefault(key, {"param": display, "url": url, "count": 0})
    item["count"] += 1


def _parameter_surface_findings(url: str, query: str, seen: set[tuple[str, str]]) -> list[dict]:
    findings: list[dict] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        lowered = name.lower()
        normalized = lowered.replace("-", "_")
        if normalized in SSRF_PARAMETERS and value.lower().startswith(("http://", "https://")) and (url, f"ssrf:{normalized}") not in seen:
            seen.add((url, f"ssrf:{normalized}"))
            findings.append({
                "type": "ssrf",
                "url": url,
                "param": name,
                "payload": value[:120],
                "evidence": "URL-valued server-side fetch style parameter observed in captured traffic",
                "confidence": "Tentative",
            })
        if normalized in IDOR_PARAMETERS and value.isdigit() and (url, f"idor:{normalized}") not in seen:
            seen.add((url, f"idor:{normalized}"))
            findings.append({
                "type": "idor",
                "url": url,
                "param": name,
                "payload": value,
                "evidence": f"Predictable identifier pattern observed: {name}={value}",
                "confidence": "Tentative",
            })
    return findings


def _jwt_findings(url: str, headers: dict[str, str], excerpt: str, seen: set[tuple[str, str]]) -> list[dict]:
    haystack = "\n".join([excerpt, headers.get("authorization", ""), headers.get("set-cookie", "")])
    match = JWT_PATTERN.search(haystack)
    if not match or (url, "jwt") in seen:
        return []
    seen.add((url, "jwt"))
    return [{
        "type": "jwt",
        "url": url,
        "param": "token",
        "payload": match.group(0)[:32] + "...",
        "evidence": "JWT-like token observed in response body or headers",
        "confidence": "Informational",
    }]


def _graphql_findings(url: str, content_type: str, excerpt: str, seen: set[tuple[str, str]]) -> list[dict]:
    lowered_url = url.lower()
    lowered_excerpt = excerpt.lower()
    looks_graphql = "/graphql" in lowered_url or "application/graphql" in content_type or "__schema" in lowered_excerpt or '"graphql"' in lowered_excerpt
    if not looks_graphql or (url, "graphql") in seen:
        return []
    seen.add((url, "graphql"))
    return [{
        "type": "graphql",
        "url": url,
        "param": "endpoint",
        "payload": "",
        "evidence": "GraphQL surface observed in captured traffic",
        "confidence": "Informational",
    }]


def _websocket_findings(url: str, headers: dict[str, str], excerpt: str, seen: set[tuple[str, str]]) -> list[dict]:
    has_upgrade = headers.get("upgrade", "").lower() == "websocket"
    match = WEBSOCKET_PATTERN.search(excerpt)
    if not has_upgrade and not match:
        return []
    endpoint = match.group(0) if match else url
    if (endpoint, "websocket") in seen:
        return []
    seen.add((endpoint, "websocket"))
    return [{
        "type": "websocket",
        "url": endpoint,
        "param": "endpoint",
        "payload": "",
        "evidence": "WebSocket endpoint or upgrade response observed in captured traffic",
        "confidence": "Informational",
    }]
