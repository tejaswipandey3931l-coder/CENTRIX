"""Live GitHub API connector for CENTRIX security findings.

Dispatches validated findings as structured GitHub Issues with severity tags,
forensic evidence, reproduction cURL PoC, and remediation guidance.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import aiohttp

from api.models import Finding, ScanState
from reporting.github_issues import format_finding_as_github_issue


class GitHubClient:
    """Async client for GitHub REST API issue creation."""

    def __init__(
        self,
        token: Optional[str] = None,
        repo: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.repo = repo or os.getenv("GITHUB_REPO", "")
        self.api_url = (api_url or os.getenv("GITHUB_API_URL", "https://api.github.com")).rstrip("/")

    def is_configured(self) -> bool:
        """Check if both token and target repository are configured."""
        return bool(self.token and self.repo and "/" in self.repo)

    async def create_issue(
        self,
        finding: Finding,
        state: Optional[ScanState] = None,
        repo: Optional[str] = None,
        labels: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Publish a security finding to a GitHub repository issue tracker."""
        target_repo = repo or self.repo
        if not self.token or not target_repo:
            return {
                "status": "queued-missing-credentials",
                "error": "GitHub connector requires GITHUB_TOKEN and GITHUB_REPO ('owner/repo').",
                "issue_id": None,
                "issue_url": None,
                "html_url": None,
            }

        from api.models import ScanConfig
        fallback_state = state or ScanState(id=finding.scan_id, config=ScanConfig(target=finding.target))
        issue_payload = format_finding_as_github_issue(finding, fallback_state)
        final_labels = list(dict.fromkeys([*issue_payload.get("labels", []), *(labels or [])]))

        req_body = {
            "title": issue_payload["title"],
            "body": issue_payload["body"],
            "labels": final_labels,
        }

        url = f"{self.api_url}/repos/{target_repo}/issues"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CENTRIX-Security-Auditor/4.0",
        }

        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=req_body, headers=headers) as resp:
                    resp_data = await resp.json()
                    if resp.status in (200, 201):
                        return {
                            "status": "sent",
                            "issue_id": resp_data.get("number"),
                            "issue_url": resp_data.get("url"),
                            "html_url": resp_data.get("html_url"),
                            "error": None,
                        }
                    else:
                        err_msg = resp_data.get("message") or f"HTTP {resp.status}"
                        return {
                            "status": "error",
                            "error": f"GitHub API rejected request: {err_msg}",
                            "status_code": resp.status,
                            "issue_id": None,
                            "issue_url": None,
                            "html_url": None,
                        }
        except Exception as exc:
            return {
                "status": "error",
                "error": f"GitHub API dispatch failed: {exc}",
                "issue_id": None,
                "issue_url": None,
                "html_url": None,
            }
