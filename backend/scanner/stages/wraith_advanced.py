"""
Wraith compatibility pass for Centrix.

This stage runs Wraith's non-SAST DAST modules through a small async adapter and
normalizes their raw findings into the shape Centrix already understands.
"""
from __future__ import annotations

import asyncio
import importlib
import os
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, urljoin, urlparse

import aiohttp


@dataclass
class _SimpleResponse:
    status_code: int
    status: int
    text: str
    headers: dict[str, str]
    url: str


class _AioHttpAdapter:
    def __init__(self, timeout: int) -> None:
        self.timeout = timeout
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "_AioHttpAdapter":
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"User-Agent": "Centrix-Wraith-Compat/1.0"},
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._session:
            await self._session.close()

    async def get(self, url: str, **kwargs) -> _SimpleResponse | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> _SimpleResponse | None:
        return await self.request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> _SimpleResponse | None:
        if not self._session:
            return None
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("ssl", False)
        try:
            async with self._session.request(method, url, **kwargs) as response:
                body = await response.text(errors="replace")
                return _SimpleResponse(
                    status_code=response.status,
                    status=response.status,
                    text=body,
                    headers=dict(response.headers),
                    url=str(response.url),
                )
        except Exception:
            return None


URL_SCANNERS: list[tuple[str, str, str]] = [
    ("scanner.modules.idor_scanner", "IDORScanner", "scan_url_async"),
    ("scanner.modules.graphql_scanner", "GraphQLScanner", "scan_url_async"),
    ("scanner.modules.hpp_scanner", "HPPScanner", "scan_url_async"),
    ("scanner.modules.mass_assignment_scanner", "MassAssignmentScanner", "scan_url_async"),
]

FORM_SCANNERS_ASYNC: list[tuple[str, str, str]] = [
    ("scanner.modules.graphql_scanner", "GraphQLScanner", "scan_form_async"),
    ("scanner.modules.hpp_scanner", "HPPScanner", "scan_form_async"),
    ("scanner.modules.mass_assignment_scanner", "MassAssignmentScanner", "scan_form_async"),
]

FORM_SCANNERS_SYNC: list[tuple[str, str, str]] = [
    ("scanner.modules.csrf_scanner", "CSRFScanner", "scan_form"),
    ("scanner.modules.crypto_scanner", "CryptoScanner", "scan_form"),
]

TARGET_SCANNERS_SYNC: list[tuple[str, str, str]] = [
    ("scanner.modules.crypto_scanner", "CryptoScanner", "scan_url"),
    ("scanner.modules.component_scanner", "ComponentScanner", "scan_base_url"),
    ("scanner.modules.wordpress_scanner", "WordPressScanner", "scan_url"),
]

AGGRESSIVE_ONLY_URL_SCANNERS: list[tuple[str, str, str]] = [
    ("scanner.modules.ssrf_scanner", "SSRFScanner", "scan_url_async"),
]

AGGRESSIVE_ONLY_FORM_SCANNERS_SYNC: list[tuple[str, str, str]] = [
    ("scanner.modules.race_scanner", "RaceConditionScanner", "scan_form"),
]


async def run(
    target: str,
    urls: list[str],
    forms: list[dict],
    evidence: list[dict],
    log: Callable[[str], Awaitable[None]],
    safety: str = "standard",
    timeout: int = 15,
    max_requests: int = 500,
) -> list[dict]:
    """Run copied Wraith non-SAST modules and return raw Centrix-style findings."""
    if safety == "passive":
        return []

    await log("[INFO] Wraith compatibility pass started")
    all_urls = _dedupe([target, *urls])[: max(1, min(max_requests // 6, 80))]
    normalized_forms = [_normalize_form(form, target=target) for form in forms[:30]]
    findings: list[dict] = []

    async with _AioHttpAdapter(timeout=timeout) as http:
        url_tasks: list[asyncio.Task[list[dict]]] = []
        for url in all_urls:
            params = _params_for_url(url)
            if not params:
                continue
            for scanner_ref in URL_SCANNERS:
                url_tasks.append(asyncio.create_task(_run_async_url_scanner(scanner_ref, url, params, http, timeout, log)))
            if safety == "aggressive":
                for scanner_ref in AGGRESSIVE_ONLY_URL_SCANNERS:
                    url_tasks.append(asyncio.create_task(_run_async_url_scanner(scanner_ref, url, params, http, timeout, log)))

        form_tasks: list[asyncio.Task[list[dict]]] = []
        for form in normalized_forms:
            for scanner_ref in FORM_SCANNERS_ASYNC:
                form_tasks.append(asyncio.create_task(_run_async_form_scanner(scanner_ref, form, http, timeout, log)))

        for result in await asyncio.gather(*url_tasks, *form_tasks, return_exceptions=True):
            if isinstance(result, list):
                findings.extend(result)

    for scanner_ref in TARGET_SCANNERS_SYNC:
        findings.extend(await _run_sync_target_scanner(scanner_ref, target, timeout, log))

    graphql_urls = _extract_graphql_urls(target, all_urls, evidence)
    if graphql_urls:
        findings.extend(await _run_graphql_advanced(graphql_urls, timeout, log))

    websocket_targets = _extract_websocket_targets(target, all_urls, evidence)
    if websocket_targets:
        if safety == "aggressive" or _enabled("CENTRIX_ENABLE_WEBSOCKET_DAST"):
            findings.extend(await _run_websocket_targets(websocket_targets, timeout, log))
        else:
            await log(f"[INFO] WebSocket active checks discovered {len(websocket_targets)} target(s); enable aggressive safety to probe frames")

    if _enabled("CENTRIX_ENABLE_GRPC_DAST"):
        grpc_finding = await _run_grpc_reflection(target, log)
        if grpc_finding:
            findings.append(grpc_finding)

    for form in normalized_forms:
        for scanner_ref in FORM_SCANNERS_SYNC:
            findings.extend(await _run_sync_form_scanner(scanner_ref, form, timeout, log))
        if safety == "aggressive":
            for scanner_ref in AGGRESSIVE_ONLY_FORM_SCANNERS_SYNC:
                findings.extend(await _run_sync_form_scanner(scanner_ref, form, timeout, log))

    # JWT is a response/corpus-style scanner, so run a lightweight token sweep
    # over captured URLs rather than sending extra target requests.
    findings.extend(await _jwt_sweep(all_urls, timeout, log))

    normalized = [_normalize_finding(item) for item in findings]
    normalized = [item for item in normalized if item.get("type")]
    await log(f"[SUCCESS] Wraith compatibility pass complete - {len(normalized)} candidates")
    return normalized


def _load_scanner(module_name: str, class_name: str, timeout: int):
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    try:
        return cls(timeout=timeout)
    except TypeError:
        return cls()


async def _run_async_url_scanner(scanner_ref, url: str, params: dict[str, str], http: _AioHttpAdapter, timeout: int, log) -> list[dict]:
    module_name, class_name, method_name = scanner_ref
    try:
        scanner = _load_scanner(module_name, class_name, timeout)
        method = getattr(scanner, method_name)
        result = await method(_base_url(url), params, http)
        return result or []
    except Exception as exc:
        await log(f"[WARN] Wraith {class_name} skipped for URL: {exc}")
        return []


async def _run_async_form_scanner(scanner_ref, form: dict, http: _AioHttpAdapter, timeout: int, log) -> list[dict]:
    module_name, class_name, method_name = scanner_ref
    try:
        scanner = _load_scanner(module_name, class_name, timeout)
        method = getattr(scanner, method_name)
        result = await method(form, http)
        return result or []
    except Exception as exc:
        await log(f"[WARN] Wraith {class_name} skipped for form: {exc}")
        return []


async def _run_sync_target_scanner(scanner_ref, target: str, timeout: int, log) -> list[dict]:
    module_name, class_name, method_name = scanner_ref
    try:
        scanner = _load_scanner(module_name, class_name, timeout)
        method = getattr(scanner, method_name)
        return await asyncio.to_thread(method, target) or []
    except Exception as exc:
        await log(f"[WARN] Wraith {class_name} skipped for target: {exc}")
        return []


async def _run_sync_form_scanner(scanner_ref, form: dict, timeout: int, log) -> list[dict]:
    module_name, class_name, method_name = scanner_ref
    try:
        scanner = _load_scanner(module_name, class_name, timeout)
        method = getattr(scanner, method_name)
        return await asyncio.to_thread(method, form) or []
    except Exception as exc:
        await log(f"[WARN] Wraith {class_name} skipped for form: {exc}")
        return []


async def _run_graphql_advanced(graphql_urls: list[str], timeout: int, log) -> list[dict]:
    try:
        from scanner.modules.graphql_advanced_scanner import GraphQLAdvancedScanner
    except Exception as exc:
        await log(f"[WARN] Wraith GraphQLAdvancedScanner unavailable: {exc}")
        return []

    findings: list[dict] = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), connector=aiohttp.TCPConnector(ssl=False)) as session:
        scanner = GraphQLAdvancedScanner(session=session)
        for graphql_url in graphql_urls[:5]:
            try:
                for item in await scanner.scan(graphql_url) or []:
                    findings.append({**item, "url": graphql_url, "param": "query"})
            except Exception as exc:
                await log(f"[WARN] Wraith GraphQL advanced skipped for {graphql_url}: {exc}")
    if findings:
        await log(f"[INFO] Wraith GraphQL advanced produced {len(findings)} candidate(s)")
    return findings


async def _run_websocket_targets(targets: list[dict], timeout: int, log) -> list[dict]:
    try:
        from scanner.modules.websocket_scanner import WebSocketScanner
    except Exception as exc:
        await log(f"[WARN] Wraith WebSocketScanner unavailable: {exc}")
        return []

    scanner = WebSocketScanner(timeout=timeout)
    findings: list[dict] = []
    for target in targets[:5]:
        try:
            findings.extend(await scanner.scan_target_async(target) or [])
        except Exception as exc:
            await log(f"[WARN] Wraith WebSocket check skipped for {target.get('url')}: {exc}")
    try:
        findings.extend(scanner.collect_oob_findings())
    except Exception:
        pass
    if findings:
        await log(f"[INFO] Wraith WebSocket checks produced {len(findings)} candidate(s)")
    return findings


async def _run_grpc_reflection(target: str, log) -> dict | None:
    try:
        from scanner.modules.grpc_scanner import GRPCScanner
    except Exception as exc:
        await log(f"[WARN] Wraith GRPCScanner unavailable: {exc}")
        return None
    parsed = urlparse(target)
    if not parsed.hostname:
        return None
    try:
        scanner = GRPCScanner(target_host=parsed.hostname, target_port=int(os.environ.get("CENTRIX_GRPC_PORT", "50051")))
        result = await asyncio.to_thread(scanner.scan_grpc_reflection)
        if result:
            result.setdefault("url", f"{parsed.hostname}:{os.environ.get('CENTRIX_GRPC_PORT', '50051')}")
            result.setdefault("param", "reflection")
            await log("[INFO] Wraith gRPC reflection produced a candidate")
        return result
    except Exception as exc:
        await log(f"[WARN] Wraith gRPC reflection skipped: {exc}")
        return None


async def _jwt_sweep(urls: list[str], timeout: int, log) -> list[dict]:
    try:
        from scanner.modules.jwt_scanner import JWTScanner
    except Exception:
        return []

    scanner = JWTScanner()
    results: list[dict] = []
    tokenish = []
    async with _AioHttpAdapter(timeout=timeout) as http:
        for url in urls[:20]:
            response = await http.get(url)
            if not response:
                continue
            tokenish.extend(_extract_jwt_like(response.text))
            for value in response.headers.values():
                tokenish.extend(_extract_jwt_like(str(value)))
    for token in _dedupe(tokenish)[:10]:
        header = scanner.decode_jwt(token)
        if header:
            results.append({
                "type": "jwt",
                "url": urls[0] if urls else "",
                "param": "token",
                "payload": token[:40],
                "evidence": f"JWT-like token exposed with header: {header}",
                "confidence": "Informational",
            })
            await log("[INFO] JWT-like token exposure candidate found")
            break
    return results


def _normalize_form(form: dict, target: str = "") -> dict:
    raw_action = form.get("action", "") or form.get("url", "")
    base = form.get("url") or target
    action = urljoin(base, raw_action) if base else raw_action
    fields = form.get("fields") or []
    if not fields and form.get("inputs"):
        fields = [{"name": name, "type": "text", "value": ""} if isinstance(name, str) else name for name in form.get("inputs", [])]
    inputs = []
    for field in fields:
        if isinstance(field, dict) and field.get("name"):
            inputs.append({
                "name": str(field.get("name", "")),
                "type": str(field.get("type", "text")),
                "value": str(field.get("value", "")),
            })
    return {
        **form,
        "action": action,
        "method": str(form.get("method", "GET")).upper(),
        "fields": inputs,
        "inputs": inputs,
    }


def _extract_graphql_urls(target: str, urls: list[str], evidence: list[dict]) -> list[str]:
    candidates: list[str] = []
    for url in urls:
        if "graphql" in url.lower():
            candidates.append(_base_url(url))
    for item in evidence or []:
        base = str(item.get("url") or target)
        body = str(item.get("response_excerpt") or "")
        if "graphql" in body.lower():
            for match in re.findall(r"""["']([^"']*graphql[^"']*)["']""", body, flags=re.I):
                candidates.append(urljoin(base, match))
    # Common endpoints are cheap to test and match Wraith's discovery style.
    for path in ("/graphql", "/api/graphql", "/graphiql"):
        candidates.append(urljoin(target.rstrip("/") + "/", path.lstrip("/")))
    return _same_origin_dedupe(target, candidates)[:8]


def _extract_websocket_targets(target: str, urls: list[str], evidence: list[dict]) -> list[dict]:
    candidates: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme in {"ws", "wss"}:
            candidates.append(url)
    for item in evidence or []:
        base = str(item.get("url") or target)
        body = str(item.get("response_excerpt") or "")
        candidates.extend(re.findall(r"""wss?://[^\s"'<>\\)]+""", body, flags=re.I))
        for match in re.findall(r"""new\s+WebSocket\s*\(\s*["']([^"']+)["']""", body, flags=re.I):
            candidates.append(_websocket_url(base, match))
        for match in re.findall(r"""["'](/[^"']*(?:socket|ws)[^"']*)["']""", body, flags=re.I):
            candidates.append(_websocket_url(base, match))
    clean = _same_origin_dedupe(target, [_websocket_url(target, item) for item in candidates])
    return [{"url": url, "messages": [{"type": "ping", "message": "centrix"}]} for url in clean[:8]]


def _websocket_url(base: str, value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme in {"ws", "wss"}:
        return value
    absolute = urljoin(base, value)
    parsed = urlparse(absolute)
    if parsed.scheme == "https":
        return parsed._replace(scheme="wss").geturl()
    if parsed.scheme == "http":
        return parsed._replace(scheme="ws").geturl()
    return absolute


def _same_origin_dedupe(target: str, values: list[str]) -> list[str]:
    target_host = urlparse(target).netloc
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc or parsed.netloc != target_host:
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_finding(item: dict) -> dict:
    if not isinstance(item, dict):
        return {}
    raw_type = str(item.get("type") or item.get("category") or "").strip()
    lowered = raw_type.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "sql_injection": "sqli",
        "blind_sqli": "sqli",
        "time_based_sqli": "sqli",
        "sqli_error": "sqli",
        "sqli_boolean_blind": "sqli",
        "sqli_time_blind": "sqli",
        "sqli_time_blind_waf_bypass": "sqli",
        "sqli_waf_bypass": "sqli",
        "sqli_oob": "sqli",
        "xss_reflected": "xss",
        "reflected_xss": "xss",
        "dom_xss": "xss",
        "xss_dom": "xss",
        "xss_stored": "xss",
        "stored_xss": "xss",
        "path_traversal": "traversal",
        "directory_traversal": "traversal",
        "open_redirect": "open_redirect",
        "csrf": "csrf",
        "server_side_request_forgery": "ssrf",
        "ssrf": "ssrf",
        "blind_ssrf": "ssrf",
        "jwt": "jwt",
        "jwt_token": "jwt",
        "graphql_introspection": "graphql_introspection",
        "graphql": "graphql",
        "graphql_dos_depth": "graphql_dos",
        "graphql_batching_bypass": "graphql_batching",
        "grpc_reflection_enabled": "grpc_reflection",
        "websocket": "websocket",
        "websocket_injection": "websocket",
        "websocket_reflection": "websocket",
        "websocket_sqli_error": "websocket",
        "websocket_blind_ssrf": "websocket",
        "ping": "",
        "ssti": "ssti",
        "server_side_template_injection": "ssti",
        "hpp": "hpp",
        "http_parameter_pollution": "hpp",
        "cmdi": "command_injection",
        "command_injection": "command_injection",
        "xxe": "xxe",
        "xml_external_entity": "xxe",
        "mass_assignment": "mass_assignment",
        "race_condition": "race_condition",
        "race": "race_condition",
        "vulnerable_component": "vulnerable_component",
        "component": "vulnerable_component",
        "wordpress": "wordpress",
        "wordpress_directory_listing": "wordpress",
        "wordpress_info_disclosure": "wordpress",
        "wordpress_user_enum": "wordpress",
        "wordpress_xmlrpc": "wordpress",
        "crypto": "crypto",
        "crypto_plaintext_http": "crypto",
        "crypto_no_https_redirect": "crypto",
        "crypto_missing_hsts": "crypto",
        "crypto_weak_hsts": "crypto",
        "crypto_invalid_certificate": "crypto",
        "crypto_weak_tls_version": "crypto",
        "crypto_weak_cipher": "crypto",
        "crypto_insecure_cookie": "crypto",
        "crypto_mixed_content": "crypto",
        "crypto_http_form_submission": "crypto",
        "crypto_sensitive_data_exposure": "crypto",
        "flag": "flag",
    }
    normalized_type = aliases.get(lowered, lowered)
    confidence = item.get("confidence", "Tentative")
    if isinstance(confidence, (int, float)):
        confidence = "Confirmed" if confidence >= 90 else "Tentative"
    if confidence not in {"Confirmed", "Tentative", "Informational"}:
        confidence = "Confirmed" if str(confidence).lower() in {"high", "critical", "true"} else "Tentative"
    return {
        "type": normalized_type,
        "url": item.get("url") or item.get("action") or item.get("target") or "",
        "param": item.get("param") or item.get("parameter") or item.get("field") or "",
        "payload": item.get("payload") or "",
        "evidence": item.get("evidence") or item.get("description") or str(item)[:500],
        "confidence": confidence,
    }


def _params_for_url(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    return {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key}


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _extract_jwt_like(text: str) -> list[str]:
    import re

    return re.findall(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*\b", text or "")
