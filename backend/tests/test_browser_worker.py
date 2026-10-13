"""Tests for Playwright headless browser worker and SPA exploration."""
import pytest
from scanner.browser.worker import BrowserWorker, BrowserDiscoveryResult


def test_browser_discovery_result_defaults():
    res = BrowserDiscoveryResult()
    assert res.urls == []
    assert res.forms == []
    assert res.evidence == []
    assert res.screenshots == []
    assert res.error == ""
    d = res.to_dict()
    assert "urls" in d
    assert "forms" in d


@pytest.mark.asyncio
async def test_browser_worker_invalid_or_mock_target():
    worker = BrowserWorker(headless=True, timeout_s=3)
    # Test handling of non-routable target
    result = await worker.explore_target(
        target_url="http://192.0.2.1:12345",
        scan_id="test-scan-123",
        max_pages=1,
        capture_screenshots=False,
    )
    # Should complete without uncaught exception
    assert isinstance(result, BrowserDiscoveryResult)
