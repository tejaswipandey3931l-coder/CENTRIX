"""Tests for advanced evidence-backed retesting and cURL reproduction."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from api.models import Finding, FindingClassification, FindingStatus, Severity, EvidenceArtifact
import db.store as store
from reporting.github_issues import build_reproduction_curl
from scanner.retest import retest_finding


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    from pathlib import Path
    test_db = tmp_path / "test_retest.db"
    monkeypatch.setattr(store, "_db_path", Path(test_db))
    monkeypatch.setattr(store, "_initialized", False)
    monkeypatch.setattr("scanner.retest.ensure_public_target", AsyncMock())
    store._init_db()
    yield


def _make_mock_session(mock_response):
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.request = MagicMock(return_value=mock_cm)
    mock_session.post = MagicMock(return_value=mock_cm)
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def test_build_reproduction_curl_get_and_post():
    """Verify build_reproduction_curl generates exact, sanitized cURL commands."""
    # 1. Test GET with parameters
    get_finding = Finding(
        id="VLN-CURL-1",
        scan_id="SCN-1",
        title="Reflected XSS",
        severity=Severity.medium,
        category="XSS",
        target="http://example.com/search",
        parameter="q",
        classification=FindingClassification.tentative,
        request_method="GET",
    )
    curl_get = build_reproduction_curl(get_finding)
    assert 'curl -i -k' in curl_get
    assert 'http://example.com/search?q=CENTRIX_TEST_PAYLOAD' in curl_get

    # 2. Test POST with custom headers, auth redaction, and request body
    post_finding = Finding(
        id="VLN-CURL-2",
        scan_id="SCN-1",
        title="SQLi in Auth API",
        severity=Severity.critical,
        category="SQLi",
        target="http://example.com/api/v1/auth",
        parameter="password",
        classification=FindingClassification.confirmed,
        evidence="syntax error at or near 'OR'",
        evidence_artifact_ids=["EV-1"],
        request_method="POST",
        request_headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer sensitive_jwt_token_999",
            "X-Tenant-ID": "tenant-corp",
        },
        request_body='{"username": "admin", "password": "\' OR 1=1--"}',
    )
    curl_post = build_reproduction_curl(post_finding)
    assert "-X POST" in curl_post
    assert '-H "Content-Type: application/json"' in curl_post
    assert '-H "X-Tenant-ID: tenant-corp"' in curl_post
    assert "Bearer [REDACTED_AUTH_TOKEN]" in curl_post
    assert "sensitive_jwt_token_999" not in curl_post
    assert '-d "{\\"username\\": \\"admin\\", \\"password\\": \\"\' OR 1=1--\\"}"' in curl_post


@pytest.mark.asyncio
async def test_retest_finding_xss_reproduced():
    """Verify retest identifies persistent unencoded XSS reflections."""
    finding = Finding(
        id="VLN-RETEST-XSS",
        scan_id="SCN-1",
        title="Reflected XSS",
        severity=Severity.medium,
        category="XSS",
        vuln_type="xss",
        target="http://example.com/profile",
        parameter="bio",
        request_method="POST",
        request_headers={"Content-Type": "application/x-www-form-urlencoded"},
        classification=FindingClassification.confirmed,
        evidence="<script>centrix_verify_token_77</script>",
        evidence_artifact_ids=["EV-1"],
    )
    await store.add_finding("SCN-1", finding)

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = AsyncMock(return_value="<html><body><div><script>centrix_verify_token_77</script></div></body></html>")

    mock_session = _make_mock_session(mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await retest_finding("VLN-RETEST-XSS")

    assert res["status"] in ("Still Open", "Open")
    assert res["reproduced"] is True
    assert "Reflected XSS reproduced" in res["details"]
    assert res["method_replayed"] == "POST"

    # Verify updated finding in DB
    updated = await store.get_finding("VLN-RETEST-XSS")
    assert updated.status in (FindingStatus.still_open, FindingStatus.open)
    assert updated.reproduction_status == "reproduced"
    assert any("EV-RETEST-" in ev for ev in updated.evidence_artifact_ids)


@pytest.mark.asyncio
async def test_retest_finding_xss_remediated():
    """Verify retest detects safe entity encoding and marks finding as Fixed."""
    finding = Finding(
        id="VLN-RETEST-FIXED",
        scan_id="SCN-1",
        title="Reflected XSS",
        severity=Severity.medium,
        category="XSS",
        vuln_type="xss",
        target="http://example.com/profile",
        parameter="bio",
        request_method="GET",
        classification=FindingClassification.confirmed,
        evidence="<script>centrix_verify_token_77</script>",
        evidence_artifact_ids=["EV-1"],
    )
    await store.add_finding("SCN-1", finding)

    # Server now safely HTML entity-encodes input
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = AsyncMock(return_value="<html><body><div>&lt;script&gt;centrix_verify_token_77&lt;/script&gt;</div></body></html>")

    mock_session = _make_mock_session(mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await retest_finding("VLN-RETEST-FIXED")

    assert res["status"] == "Fixed"
    assert res["reproduced"] is False
    assert "safely HTML entity-encoded" in res["details"]

    updated = await store.get_finding("VLN-RETEST-FIXED")
    assert updated.status == FindingStatus.fixed
    assert updated.reproduction_status == "remediated"


@pytest.mark.asyncio
async def test_retest_finding_idor_auth_boundary():
    """Verify IDOR retest verifies HTTP 401/403 authorization boundaries."""
    finding = Finding(
        id="VLN-RETEST-IDOR",
        scan_id="SCN-1",
        title="IDOR in Billing Records",
        severity=Severity.high,
        category="Access Control",
        vuln_type="idor",
        target="http://example.com/api/invoices/9981",
        classification=FindingClassification.probable,
        evidence="invoice total: $45,000",
        evidence_artifact_ids=["EV-1"],
    )
    await store.add_finding("SCN-1", finding)

    # Target now rejects unauthenticated / cross-tenant request with 403 Forbidden
    mock_resp = AsyncMock()
    mock_resp.status = 403
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = AsyncMock(return_value='{"error": "Forbidden: Tenant access restricted"}')

    mock_session = _make_mock_session(mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await retest_finding("VLN-RETEST-IDOR")

    assert res["status"] == "Fixed"
    assert res["reproduced"] is False
    assert "Authorization enforced (HTTP 403)" in res["details"]
