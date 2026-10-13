"""Target and scope safety controls shared by scanner stages."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from fnmatch import fnmatch
from typing import Optional
from urllib.parse import urlparse


class TargetSafetyError(ValueError):
    """Raised when a target could reach a local or non-public network."""


DEFAULT_EXCLUDED_PATTERNS = [
    "*logout*",
    "*signout*",
    "*sign-out*",
    "*log-out*",
    "*delete-account*",
    "*account/delete*",
    "*user/delete*",
    "*billing/cancel*",
    "*admin/reset*",
    "*password/reset*",
    "*reset-password*",
    "*destroy*",
    "*unsubscribe*",
]

DESTRUCTIVE_PATH_KEYWORDS = [
    "delete",
    "drop",
    "purge",
    "truncate",
    "cancel",
    "terminate",
    "destroy",
    "remove_account",
]


def normalise_target(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetSafetyError("Target must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise TargetSafetyError("Targets containing credentials are not allowed")
    return parsed.geturl()


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global


async def ensure_public_target(url: str) -> None:
    """Resolve a hostname and reject loopback, RFC1918, link-local and reserved IPs."""
    parsed = urlparse(normalise_target(url))
    host = parsed.hostname or ""
    try:
        records = await asyncio.get_running_loop().getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetSafetyError(f"Could not resolve target hostname: {host}") from exc
    addresses = {record[4][0] for record in records}
    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise TargetSafetyError("Targets resolving to private, local, or reserved addresses are not allowed")


def url_in_scope(
    url: str,
    target: str,
    patterns: Optional[list[str]] = None,
    excluded_patterns: Optional[list[str]] = None,
) -> bool:
    """Allow target origin by default; supports explicit scope patterns and excluded paths."""
    candidate = urlparse(url)
    base = urlparse(target)

    if candidate.scheme not in {"http", "https"}:
        return False

    # Check origin match or wildcard scope
    patterns = [p.strip() for p in (patterns or []) if p.strip()]
    c_host = (candidate.hostname or "").lower()
    b_host = (base.hostname or "").lower()

    in_domain = False
    if candidate.netloc == base.netloc or c_host == b_host:
        in_domain = True
    else:
        # Allow subdomains only if an explicit wildcard pattern matching base host is present
        for pattern in patterns:
            p_strip = pattern.strip().lower()
            if p_strip.startswith("*."):
                allowed_suffix = p_strip.lstrip("*.")
                if (c_host == allowed_suffix or c_host.endswith(f".{allowed_suffix}")) and (b_host == allowed_suffix or b_host.endswith(f".{allowed_suffix}")):
                    in_domain = True
                    break
            elif "://" in p_strip:
                p_parsed = urlparse(p_strip)
                if p_parsed.netloc == candidate.netloc:
                    in_domain = True
                    break

    if not in_domain:
        return False

    clean_url = url.split("#", 1)[0]
    path = candidate.path.lower()

    # Check excluded patterns (logout, delete account, billing, etc.)
    all_excluded = [*DEFAULT_EXCLUDED_PATTERNS, *(excluded_patterns or [])]
    for exc in all_excluded:
        exc_clean = exc.strip().lower()
        if exc_clean and (fnmatch(clean_url.lower(), exc_clean) or fnmatch(path, exc_clean)):
            return False

    # If explicit inclusion patterns are provided, at least one must match
    if patterns:
        matched = False
        for pattern in patterns:
            p_strip = pattern.strip()
            p_lower = p_strip.lower()
            if p_lower.startswith("*."):
                clean_p_host = p_lower.lstrip("*.")
                if c_host == clean_p_host or c_host.endswith(f".{clean_p_host}") or fnmatch(c_host, p_lower):
                    matched = True
                    break
            if fnmatch(clean_url.lower(), p_lower) or fnmatch(path, p_lower) or p_lower in clean_url.lower():
                matched = True
                break
        return matched

    return True


def is_destructive_action(method: str, url: str) -> bool:
    """Determine whether an HTTP request executes an irreversible destructive action."""
    upper_method = method.upper().strip()
    if upper_method == "DELETE":
        return True
    if upper_method in {"POST", "PUT", "PATCH"}:
        path = urlparse(url).path.lower()
        for keyword in DESTRUCTIVE_PATH_KEYWORDS:
            if keyword in path:
                return True
    return False


def validate_request_safety(
    method: str,
    url: str,
    target: str,
    scope: Optional[list[str]] = None,
    excluded_patterns: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Pre-flight check for HTTP requests: verifies scope and blocks destructive actions."""
    if not url_in_scope(url, target, patterns=scope, excluded_patterns=excluded_patterns):
        return False, f"Out of scope or excluded target URL: {url}"

    if is_destructive_action(method, url):
        return False, f"Blocked destructive action [{method} {url}] by safety guardrails"

    return True, ""


class AdaptiveRateLimiter:
    """Token-bucket style rate limiter with automatic exponential backoff."""

    def __init__(self, max_rps: int = 10, max_concurrency: int = 5):
        self.max_rps = max(1, max_rps)
        self.semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._min_interval = 1.0 / self.max_rps
        self._last_request_time: float = 0.0
        self._backoff_delay: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to send a request, obeying rate limit and active backoff."""
        await self.semaphore.acquire()
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            target_wait = self._min_interval + self._backoff_delay
            if elapsed < target_wait:
                await asyncio.sleep(target_wait - elapsed)
            self._last_request_time = time.monotonic()

    def release(self) -> None:
        """Release semaphore concurrency ticket."""
        self.semaphore.release()

    def report_response(self, status_code: int, duration_s: float) -> None:
        """Adjust backoff based on server response (429, 503, or slow latency)."""
        if status_code in {429, 503} or duration_s > 3.0:
            self._backoff_delay = min(8.0, (self._backoff_delay or 0.5) * 2.0)
        elif status_code < 400 and duration_s < 1.0:
            self._backoff_delay = max(0.0, self._backoff_delay - 0.25)
