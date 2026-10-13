"""Detector-specific validation and observation-vs-vulnerability classification."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .baseline import compare_responses, detect_error_or_waf
from .scorer import calculate_evidence_score, EvidenceScoreCard


OBSERVATION_TYPES = {
    "missing_header",
    "graphql",
    "graphql_introspection",
    "websocket",
    "grpc_reflection",
    "vulnerable_component",
    "wordpress",
    "banner",
    "tech_detect",
    "crypto",
}

SUSPICIOUS_PARAM_NAMES = {
    "id", "user_id", "account_id", "uid", "url", "redirect", "dest", "next", "file", "path"
}


def is_observation_signal(vuln_type: str, evidence: str = "", param: str = "") -> bool:
    """Returns True if the finding is an observation/hardening signal rather than verified exploit."""
    if vuln_type in OBSERVATION_TYPES:
        return True
    if vuln_type == "jwt" and "token detected" in evidence.lower():
        return True
    if vuln_type == "idor" and not any(kw in evidence.lower() for kw in ["differential", "unauthorized access", "tenant mismatch"]):
        return True
    if vuln_type == "ssrf" and not any(kw in evidence.lower() for kw in ["callback received", "oob verified", "outbound request confirmed"]):
        return True
    if vuln_type == "csrf" and not any(kw in evidence.lower() for kw in ["state change confirmed", "replayed cross-origin"]):
        return True
    return False


def validate_xss_candidate(candidate_response_body: str, payload: str) -> dict[str, Any]:
    """
    Verifies whether reflected input is actually executable or properly HTML/URL encoded.
    E.g., if '<script>' is reflected as '&lt;script&gt;', it is harmless.
    """
    if not payload or not candidate_response_body:
        return {"is_executable": False, "is_encoded": False, "reasons": ["Missing payload or response"]}

    # If payload contains HTML special chars, check if they are encoded in the response
    special_chars = ["<", ">", "\"", "'"]
    has_specials = any(c in payload for c in special_chars)

    if has_specials:
        encoded_variants = []
        if "<" in payload or ">" in payload:
            encoded_variants.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
        if '"' in payload:
            encoded_variants.append(payload.replace('"', "&quot;"))
        if "'" in payload:
            encoded_variants.append(payload.replace("'", "&#39;"))
            encoded_variants.append(payload.replace("'", "&apos;"))

        raw_reflected = payload in candidate_response_body
        is_encoded = any(variant in candidate_response_body for variant in encoded_variants if variant != payload)

        if raw_reflected:
            stripped = candidate_response_body.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                return {
                    "is_executable": False,
                    "is_encoded": False,
                    "reasons": ["Payload reflected in JSON data structure (non-executable context)."],
                }
            return {
                "is_executable": True,
                "is_encoded": False,
                "reasons": ["Unencoded HTML/JS reflection verified in response body."],
            }
        elif is_encoded:
            return {
                "is_executable": False,
                "is_encoded": True,
                "reasons": ["Payload characters are safely HTML-encoded in response."],
            }


    # If payload does not contain special characters (canary probe only)
    if payload in candidate_response_body:
        return {
            "is_executable": False,
            "is_encoded": False,
            "reasons": ["Canary marker reflected, but no execution vector confirmed."],
        }

    return {"is_executable": False, "is_encoded": False, "reasons": ["Payload not reflected in response."]}


def validate_csrf_candidate(
    method: str,
    has_state_change: bool,
    has_samesite_cookie: bool,
    has_anti_csrf_token: bool,
    allows_cross_origin: bool,
) -> dict[str, Any]:
    """
    Validates whether a form / endpoint is genuinely vulnerable to CSRF:
    - Must be state-changing (not GET or readonly)
    - Must be replayable without valid CSRF protection or SameSite=Strict
    """
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return {
            "is_vulnerable": False,
            "reasons": ["Idempotent safe HTTP method (GET/HEAD). Not eligible for CSRF."],
        }

    if not has_state_change:
        return {
            "is_vulnerable": False,
            "reasons": ["Endpoint does not perform state-changing operations."],
        }

    if has_anti_csrf_token:
        return {
            "is_vulnerable": False,
            "reasons": ["Form/Request includes anti-CSRF token defense."],
        }

    if has_samesite_cookie and not allows_cross_origin:
        return {
            "is_vulnerable": False,
            "reasons": ["SameSite cookie protections mitigate cross-origin execution."],
        }

    return {
        "is_vulnerable": True,
        "reasons": ["State-changing request lacks anti-CSRF tokens and SameSite protection."],
    }


def validate_ssrf_candidate(
    url_param_value: str,
    has_outbound_callback: bool,
    target_host: str,
) -> dict[str, Any]:
    """
    Evaluates SSRF candidate:
    - Having a URL-valued parameter is merely an SSRF candidate (Tentative).
    - Only confirmed if out-of-band / callback infrastructure verifies the server actually initiated the outbound fetch.
    """
    if has_outbound_callback:
        return {
            "is_vulnerable": True,
            "reasons": ["Out-of-band callback verified server-initiated network request."],
        }

    return {
        "is_vulnerable": False,
        "reasons": ["URL parameter observed, but no outbound server request confirmed."],
    }


def validate_idor_candidate(
    param_name: str,
    param_value: str,
    has_differential_authz_evidence: bool,
) -> dict[str, Any]:
    """
    Evaluates IDOR candidate:
    - Numeric `id` or predictable parameter is only a candidate.
    - Requires differential authorization evidence (e.g. User B accessing User A resource) to confirm.
    """
    if has_differential_authz_evidence:
        return {
            "is_vulnerable": True,
            "reasons": ["Cross-identity access control discrepancy verified with test evidence."],
        }

    return {
        "is_vulnerable": False,
        "reasons": ["Predictable identifier detected, but access-control bypass is unverified."],
    }


def redact_sensitive_tokens(text: str) -> str:
    """Redacts JWTs, bearer tokens, passwords, and private keys in logs and findings."""
    if not isinstance(text, str):
        return text

    # Redact JWTs (header.payload.signature)
    jwt_pattern = r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    redacted = re.sub(jwt_pattern, "eyJ[REDACTED_JWT_TOKEN]", text)

    # Redact Authorization headers
    auth_pattern = r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}"
    redacted = re.sub(auth_pattern, r"\1[REDACTED_BEARER]", redacted, flags=re.IGNORECASE)

    # Redact Passwords
    pass_pattern = r'("(password|passwd|api_key|token)"\s*:\s*")[^"]+(")'
    redacted = re.sub(pass_pattern, r'\1[REDACTED_SECRET]\3', redacted, flags=re.IGNORECASE)

    return redacted
