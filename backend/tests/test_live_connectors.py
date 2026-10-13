"""Tests for real GitHub and Jira API connectors and integration routes."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from api.models import Finding, FindingClassification, Severity, ScanState, ScanConfig
from integrations.github import GitHubClient
from integrations.jira import JiraClient
import db.store as store
from api.routes.integrations import push_finding, integration_status, PushFindingRequest


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    from pathlib import Path
    test_db = tmp_path / "test_connectors.db"
    monkeypatch.setattr(store, "_db_path", Path(test_db))
    monkeypatch.setattr(store, "_initialized", False)
    store._init_db()
    yield


def _make_mock_session(mock_response):
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_cm)
    mock_session.request = MagicMock(return_value=mock_cm)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


@pytest.mark.asyncio
async def test_github_client_unconfigured():
    """Verify GitHubClient cleanly reports missing credentials when unconfigured."""
    client = GitHubClient(token="", repo="")
    assert not client.is_configured()

    finding = Finding(
        id="VLN-TEST1",
        scan_id="SCN-1",
        title="Stored XSS in Comment Box",
        severity=Severity.high,
        category="XSS",
        target="http://example.com/comments",
        classification=FindingClassification.confirmed,
        evidence="<script>alert(1)</script>",
        evidence_artifact_ids=["EV-1"],
    )

    result = await client.create_issue(finding)
    assert result["status"] == "queued-missing-credentials"
    assert "requires GITHUB_TOKEN" in result["error"]
    assert result["issue_id"] is None


@pytest.mark.asyncio
async def test_github_client_success():
    """Verify GitHubClient successfully issues API call and extracts issue details."""
    client = GitHubClient(token="ghp_fake_token_12345", repo="acme/security-target")
    assert client.is_configured()

    finding = Finding(
        id="VLN-TEST2",
        scan_id="SCN-1",
        title="SQL Injection in Login Form",
        severity=Severity.critical,
        category="SQLi",
        target="http://example.com/api/login",
        classification=FindingClassification.confirmed,
        evidence="syntax error at or near 'OR'",
        evidence_artifact_ids=["EV-1"],
        cwe="CWE-89",
        cvss=9.8,
    )

    mock_response = AsyncMock()
    mock_response.status = 201
    mock_response.json = AsyncMock(return_value={
        "number": 42,
        "url": "https://api.github.com/repos/acme/security-target/issues/42",
        "html_url": "https://github.com/acme/security-target/issues/42",
    })

    mock_session = _make_mock_session(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await client.create_issue(finding)

    assert res["status"] == "sent"
    assert res["issue_id"] == 42
    assert res["html_url"] == "https://github.com/acme/security-target/issues/42"
    assert res["error"] is None


@pytest.mark.asyncio
async def test_jira_client_unconfigured():
    """Verify JiraClient cleanly reports missing credentials when unconfigured."""
    client = JiraClient(url="", email="", api_token="", project_key="")
    assert not client.is_configured()

    finding = Finding(
        id="VLN-TEST3",
        scan_id="SCN-1",
        title="IDOR in User Profile",
        severity=Severity.high,
        category="Access Control",
        target="http://example.com/api/users/12",
        classification=FindingClassification.probable,
        evidence="Differential access",
    )

    result = await client.create_issue(finding)
    assert result["status"] == "queued-missing-credentials"
    assert "JIRA_URL" in result["error"]
    assert result["issue_key"] is None


@pytest.mark.asyncio
async def test_jira_client_success():
    """Verify JiraClient generates valid basic auth and issue creation payload."""
    client = JiraClient(
        url="https://acme.atlassian.net",
        email="sec-bot@acme.com",
        api_token="api_token_abc_xyz",
        project_key="SEC",
        issue_type="Bug",
    )
    assert client.is_configured()

    finding = Finding(
        id="VLN-TEST4",
        scan_id="SCN-1",
        title="Path Traversal in Download Endpoint",
        severity=Severity.critical,
        category="Path Traversal",
        target="http://example.com/download",
        classification=FindingClassification.confirmed,
        evidence="root:x:0:0:root:/root",
        evidence_artifact_ids=["EV-1"],
        cwe="CWE-22",
    )

    mock_response = AsyncMock()
    mock_response.status = 201
    mock_response.json = AsyncMock(return_value={
        "id": "10042",
        "key": "SEC-42",
        "self": "https://acme.atlassian.net/rest/api/2/issue/10042",
    })

    mock_session = _make_mock_session(mock_response)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await client.create_issue(finding)

    assert res["status"] == "sent"
    assert res["issue_key"] == "SEC-42"
    assert res["issue_id"] == "10042"
    assert res["issue_url"] == "https://acme.atlassian.net/browse/SEC-42"
    assert res["error"] is None


@pytest.mark.asyncio
async def test_push_finding_route_live_dispatch():
    """Verify POST /api/integrations/findings/{id}/push routes to connectors and records outbox."""
    scan = ScanState(
        id="SCN-DISPATCH-1",
        config=ScanConfig(target="http://example.com", authorized=True),
    )
    await store.create_scan(scan)

    finding = Finding(
        id="VLN-DISPATCH-1",
        scan_id="SCN-DISPATCH-1",
        title="Reflected XSS",
        severity=Severity.medium,
        category="XSS",
        target="http://example.com/search",
        classification=FindingClassification.confirmed,
        evidence="<script>alert(1)</script>",
        evidence_artifact_ids=["EV-1"],
    )
    await store.add_finding("SCN-DISPATCH-1", finding)

    # Push to GitHub with mock
    mock_gh = AsyncMock()
    mock_gh.create_issue.return_value = {
        "status": "sent",
        "issue_id": 99,
        "issue_url": "https://api.github.com/repos/owner/repo/issues/99",
        "html_url": "https://github.com/owner/repo/issues/99",
        "error": None,
    }

    with patch("api.routes.integrations.GitHubClient", return_value=mock_gh):
        req = PushFindingRequest(destination="github", note="Urgent triage")
        gh_res = await push_finding("VLN-DISPATCH-1", req)

    assert gh_res["status"] == "sent"
    assert gh_res["external_id"] == "99"
    assert gh_res["external_url"] == "https://github.com/owner/repo/issues/99"

    # Verify audit in store
    outbox = await store.list_integration_outbox("VLN-DISPATCH-1")
    assert len(outbox) == 1
    assert outbox[0]["destination"] == "github"
    assert outbox[0]["status"] == "sent"
