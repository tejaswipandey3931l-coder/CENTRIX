"""Response similarity, baseline comparison, and dynamic noise normalization engine.

Filters out noise:
- Dates & ISO timestamps
- Request IDs & UUIDs
- CSRF tokens & session cookies
- Nonces & cache-busters
- Analytics IDs & tracking params
- Custom 404s, login redirects, WAF blocks, and generic errors.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


# Precompiled regex patterns for normalization
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ISO timestamps / standard dates
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?\b"), "[DATETIME]"),
    (re.compile(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b", re.IGNORECASE), "[HTTP_DATE]"),
    (re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"), "[DATE]"),
    # Unix epoch timestamps (seconds or milliseconds)
    (re.compile(r"\b1[5-7]\d{8,11}\b"), "[TIMESTAMP]"),
    # UUIDs
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "[UUID]"),
    # Standard 32/64 char hex hashes (md5/sha256 tokens)
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), "[HEX32]"),
    (re.compile(r"\b[0-9a-fA-F]{64}\b"), "[HEX64]"),
    # CSRF tokens in HTML / JSON
    (re.compile(r'(name=["\'](csrf[-_]?token|_token|authenticity_token|csrfmiddlewaretoken)["\']\s+value=["\'])[^"\']+(["\'])', re.IGNORECASE), r"\g<1>[CSRF_TOKEN]\g<3>"),
    (re.compile(r'("(csrf[-_]?token|_token|authenticity_token|csrfmiddlewaretoken)"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\g<1>[CSRF_TOKEN]\g<3>"),
    # HTML Script nonces and JSON nonces
    (re.compile(r'nonce=["\'][^"\']+["\']', re.IGNORECASE), 'nonce="[NONCE]"'),
    (re.compile(r'("nonce"\s*:\s*")[^"]+(")', re.IGNORECASE), r'\g<1>[NONCE]\g<2>'),
    # Cache busters & query tracking
    (re.compile(r'([?&](_|\bv|t|ts|timestamp|utm_[a-z]+|_ga|_gid))=[^&"\s]+', re.IGNORECASE), r"\g<1>=[TRACKING]"),
    # Session cookies
    (re.compile(r"(JSESSIONID|PHPSESSID|connect\.sid|sessionid)=[^;\s]+", re.IGNORECASE), r"\g<1>=[SESSION_ID]"),
]

# WAF block signatures
_WAF_SIGNATURES: list[str] = [
    "cloudflare",
    "attention required! | cloudflare",
    "access denied",
    "request blocked by security rule",
    "incident id",
    "web application firewall",
    "akamai",
    "imperva",
    "incapsula",
    "aws waf",
    "mod_security",
    "sucuri",
]

# Generic 404 signatures
_CUSTOM_404_SIGNATURES: list[str] = [
    "page not found",
    "404 not found",
    "the page you requested could not be found",
    "resource not found",
    "cannot find the requested page",
    "error 404",
]


def normalize_response_body(body: str) -> str:
    """Normalizes away dates, request IDs, CSRF tokens, session IDs, and tracking parameters."""
    if not isinstance(body, str) or not body:
        return ""

    cleaned = body
    for pattern, replacement in _PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)

    # Collapse multiple whitespaces
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def compute_structural_hash(html_or_json: str) -> str:
    """
    Computes a structural skeleton hash invariant to dynamic content.
    For HTML: extracts sequence of HTML tag names.
    For JSON: extracts nested key hierarchy.
    """
    if not html_or_json:
        return hashlib.md5(b"").hexdigest()

    # Check if JSON
    text = html_or_json.strip()
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        try:
            data = json.loads(text)
            def extract_keys(obj: Any) -> list:
                if isinstance(obj, dict):
                    return sorted(list(obj.keys())) + [extract_keys(v) for v in obj.values()]
                elif isinstance(obj, list) and obj:
                    return ["list_item", extract_keys(obj[0])]
                return ["val"]
            keys_skeleton = str(extract_keys(data))
            return hashlib.md5(keys_skeleton.encode()).hexdigest()
        except Exception:
            pass

    # HTML tag extraction
    tags = re.findall(r"<([a-zA-Z0-9]+)[\s>]", html_or_json)
    if tags:
        tag_skeleton = ":".join(t.lower() for t in tags[:200])
        return hashlib.md5(tag_skeleton.encode()).hexdigest()

    # Fallback to normalized text length bucket
    return hashlib.md5(str(len(normalize_response_body(html_or_json)) // 50).encode()).hexdigest()


def detect_error_or_waf(status_code: int, body: str, headers: Optional[dict[str, str]] = None) -> dict[str, bool]:
    """Detects custom 404, WAF blocks, login redirects, and generic errors."""
    body_lower = (body or "").lower()
    headers_dict = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}

    # 1. Custom 404
    is_custom_404 = (
        status_code == 404
        or any(sig in body_lower for sig in _CUSTOM_404_SIGNATURES)
    )

    # 2. Login Redirect
    location = headers_dict.get("location", "")
    is_login_redirect = (
        status_code in (301, 302, 303, 307, 308)
        and any(x in location for x in ["/login", "/signin", "/auth", "/session/new", "/accounts/"])
    ) or (
        status_code == 200
        and "<input type=\"password\"" in body_lower
        and any(x in body_lower for x in ["log in", "sign in", "password"])
    )

    # 3. WAF Block
    server_header = headers_dict.get("server", "")
    is_waf_block = (
        status_code in (403, 406, 429)
        and (
            any(sig in body_lower for sig in _WAF_SIGNATURES)
            or any(sig in server_header for sig in ["cloudflare", "akamai", "imperva", "sucuri"])
        )
    ) or any(sig in body_lower for sig in ["attention required! | cloudflare", "access denied", "incident id"])

    # 4. Generic Server Error
    is_generic_error = (
        status_code in (500, 502, 503, 504)
        or any(x in body_lower for x in ["internal server error", "bad gateway", "service unavailable"])
    )

    return {
        "is_custom_404": is_custom_404,
        "is_login_redirect": is_login_redirect,
        "is_waf_block": is_waf_block,
        "is_generic_error": is_generic_error,
    }


def compare_responses(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """
    Compares baseline and candidate responses to determine if differences are meaningful
    or just random timestamps, cache changes, or generic errors.
    """
    base_status = int(baseline.get("status_code") or 200)
    cand_status = int(candidate.get("status_code") or 200)

    base_raw = str(baseline.get("body") or "")
    cand_raw = str(candidate.get("body") or "")

    base_norm = normalize_response_body(base_raw)
    cand_norm = normalize_response_body(cand_raw)

    base_struct = compute_structural_hash(base_raw)
    cand_struct = compute_structural_hash(cand_raw)

    base_len = len(base_norm)
    cand_len = len(cand_norm)
    len_diff = abs(cand_len - base_len)

    # Detect WAF / error states
    flags = detect_error_or_waf(cand_status, cand_raw, candidate.get("headers"))

    # False positive flags
    fp_indicators: list[str] = []
    if flags["is_custom_404"]:
        fp_indicators.append("Candidate triggered custom 404 page.")
    if flags["is_login_redirect"]:
        fp_indicators.append("Candidate redirected to authentication / login.")
    if flags["is_waf_block"]:
        fp_indicators.append("Candidate triggered WAF / Bot protection challenge.")
    if flags["is_generic_error"]:
        fp_indicators.append("Candidate returned generic 5xx application error.")

    # Check if normalized responses are identical despite raw difference
    raw_diff = (base_raw != cand_raw)
    norm_diff = (base_norm != cand_norm)
    if raw_diff and not norm_diff:
        fp_indicators.append("Difference was purely dynamic timestamps, nonces, or tokens.")

    # Meaningful difference: structural change or significant normalized text change
    # that is NOT a WAF block or generic 404
    meaningful = (
        norm_diff
        and not flags["is_custom_404"]
        and not flags["is_login_redirect"]
        and not flags["is_waf_block"]
        and not (len_diff < 10 and base_struct == cand_struct)
    )

    return {
        "baseline_status": base_status,
        "candidate_status": cand_status,
        "baseline_length": base_len,
        "candidate_length": cand_len,
        "length_delta": len_diff,
        "baseline_structural_hash": base_struct,
        "candidate_structural_hash": cand_struct,
        "structural_difference": (base_struct != cand_struct),
        "meaningful_difference": meaningful,
        "false_positive_indicators": fp_indicators,
        **flags,
    }
