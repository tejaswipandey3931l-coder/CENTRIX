"""Tests for scope boundary rules, excluded paths, and safety guardrails."""
import pytest
import asyncio
from scanner.safety import (
    url_in_scope,
    is_destructive_action,
    validate_request_safety,
    AdaptiveRateLimiter,
)


def test_url_in_scope_default_origin():
    assert url_in_scope("https://app.example.com/dashboard", "https://app.example.com") is True
    assert url_in_scope("https://other.com/dashboard", "https://app.example.com") is False


def test_url_in_scope_wildcard_subdomain():
    assert url_in_scope("https://api.example.com/v1", "https://example.com", patterns=["*.example.com"]) is True
    assert url_in_scope("https://auth.example.com/login", "https://example.com", patterns=["*.example.com"]) is True
    assert url_in_scope("https://malicious.net/login", "https://example.com", patterns=["*.example.com"]) is False


def test_url_in_scope_excluded_paths():
    target = "https://app.example.com"
    # Built-in excluded patterns (logout, delete account, billing)
    assert url_in_scope("https://app.example.com/logout", target) is False
    assert url_in_scope("https://app.example.com/auth/signout", target) is False
    assert url_in_scope("https://app.example.com/settings/delete-account", target) is False
    assert url_in_scope("https://app.example.com/user/password/reset", target) is False
    # Safe paths
    assert url_in_scope("https://app.example.com/api/products", target) is True
    assert url_in_scope("https://app.example.com/profile", target) is True


def test_is_destructive_action():
    assert is_destructive_action("DELETE", "https://app.example.com/api/users/42") is True
    assert is_destructive_action("POST", "https://app.example.com/api/account/delete") is True
    assert is_destructive_action("POST", "https://app.example.com/admin/database/purge") is True
    assert is_destructive_action("GET", "https://app.example.com/api/account/delete") is False
    assert is_destructive_action("GET", "https://app.example.com/items") is False
    assert is_destructive_action("POST", "https://app.example.com/api/search") is False


def test_validate_request_safety():
    target = "https://app.example.com"
    ok, _ = validate_request_safety("GET", "https://app.example.com/api/items", target)
    assert ok is True

    # Out of scope
    ok, reason = validate_request_safety("GET", "https://attacker.com/api", target)
    assert ok is False
    assert "Out of scope" in reason

    # Excluded path
    ok, reason = validate_request_safety("GET", "https://app.example.com/auth/logout", target)
    assert ok is False
    assert "Out of scope or excluded" in reason

    # Destructive action
    ok, reason = validate_request_safety("DELETE", "https://app.example.com/api/database/purge", target)
    assert ok is False
    assert "Blocked destructive action" in reason


@pytest.mark.asyncio
async def test_adaptive_rate_limiter_backoff():
    limiter = AdaptiveRateLimiter(max_rps=20, max_concurrency=2)
    assert limiter._backoff_delay == 0.0

    # Report 429 response
    limiter.report_response(429, 0.2)
    assert limiter._backoff_delay > 0.0

    # Backoff delay increases on another 503
    first_delay = limiter._backoff_delay
    limiter.report_response(503, 0.5)
    assert limiter._backoff_delay > first_delay

    # Gradual recovery on fast 200 OK
    current_delay = limiter._backoff_delay
    limiter.report_response(200, 0.1)
    assert limiter._backoff_delay < current_delay
