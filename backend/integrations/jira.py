"""Live Jira REST API connector for CENTRIX security findings.

Publishes findings directly to Atlassian Jira issue trackers with priority mapping,
CWE/CVSS fields, reproduction steps, and remediation guidance.
"""
from __future__ import annotations

import base64
import os
from typing import Any, Optional

import aiohttp

from api.models import Finding, ScanState
from reporting.remediation import get_remediation_guide


class JiraClient:
    """Async client for Atlassian Jira REST API issue creation."""

    def __init__(
        self,
        url: Optional[str] = None,
        email: Optional[str] = None,
        api_token: Optional[str] = None,
        project_key: Optional[str] = None,
        issue_type: Optional[str] = None,
    ):
        self.url = (url or os.getenv("JIRA_URL", "")).rstrip("/")
        self.email = email or os.getenv("JIRA_EMAIL", "")
        self.api_token = api_token or os.getenv("JIRA_API_TOKEN", "")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "")
        self.issue_type = issue_type or os.getenv("JIRA_ISSUE_TYPE", "Bug")

    def is_configured(self) -> bool:
        """Check if all required Jira Cloud credentials are present."""
        return bool(self.url and self.email and self.api_token and self.project_key)

    async def create_issue(
        self,
        finding: Finding,
        state: Optional[ScanState] = None,
        project_key: Optional[str] = None,
        issue_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a Jira ticket from a validated security finding."""
        target_project = project_key or self.project_key
        target_type = issue_type or self.issue_type

        if not (self.url and self.email and self.api_token and target_project):
            return {
                "status": "queued-missing-credentials",
                "error": "Jira connector requires JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY.",
                "issue_key": None,
                "issue_id": None,
                "issue_url": None,
            }

        auth_str = f"{self.email}:{self.api_token}".encode("utf-8")
        basic_auth = base64.b64encode(auth_str).decode("utf-8")

        sev = finding.severity.value
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }
        priority_name = priority_map.get(sev.lower(), "Medium")

        guide = get_remediation_guide(finding.category or finding.vuln_type)
        summary = f"[CENTRIX] [{sev}] {finding.title} ({finding.target})"[:250]

        description = (
            f"h2. Security Vulnerability Alert\n\n"
            f"*Target URL:* {finding.target}\n"
            f"*Severity:* {sev}\n"
            f"*Classification:* {finding.classification.value}\n"
            f"*Confidence Score:* {finding.confidence_score}/10\n"
            f"*CWE:* {finding.cwe or 'N/A'}\n"
            f"*CVSS:* {finding.cvss or 'N/A'}\n"
            f"*Parameter:* {finding.parameter or 'N/A'}\n\n"
            f"h3. Impact & Description\n"
            f"{finding.description or guide.get('summary', 'Vulnerability detected by CENTRIX audit.')}\n\n"
            f"h3. Forensic Evidence\n"
            f"{{noformat}}\n{finding.evidence[:1500] or 'Direct behavioral proof collected during scan.'}\n{{noformat}}\n\n"
            f"h3. Remediation Checklist\n"
        )
        for chk in guide.get("prevention_checklist", []):
            description += f"* {chk}\n"

        labels = [
            "security",
            "centrix-finding",
            f"sev-{sev.lower()}",
        ]
        if finding.cwe:
            labels.append(finding.cwe.lower().replace("-", ""))

        req_body = {
            "fields": {
                "project": {"key": target_project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": target_type},
                "priority": {"name": priority_name},
                "labels": labels,
            }
        }

        endpoint = f"{self.url}/rest/api/2/issue"
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CENTRIX-Security-Auditor/4.0",
        }

        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(endpoint, json=req_body, headers=headers) as resp:
                    resp_data = await resp.json()
                    if resp.status in (200, 201):
                        key = resp_data.get("key")
                        issue_id = resp_data.get("id")
                        browser_url = f"{self.url}/browse/{key}" if key else resp_data.get("self")
                        return {
                            "status": "sent",
                            "issue_key": key,
                            "issue_id": issue_id,
                            "issue_url": browser_url,
                            "error": None,
                        }
                    else:
                        errors = resp_data.get("errors") or resp_data.get("errorMessages") or f"HTTP {resp.status}"
                        return {
                            "status": "error",
                            "error": f"Jira API rejected issue: {errors}",
                            "status_code": resp.status,
                            "issue_key": None,
                            "issue_id": None,
                            "issue_url": None,
                        }
        except Exception as exc:
            return {
                "status": "error",
                "error": f"Jira API dispatch failed: {exc}",
                "issue_key": None,
                "issue_id": None,
                "issue_url": None,
            }
