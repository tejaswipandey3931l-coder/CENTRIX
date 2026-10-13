"""JIRA issue import formatter for CENTRIX findings."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from api.models import Finding, ScanState
from reporting.remediation import get_remediation_guide


def _map_jira_priority(severity: str) -> str:
    return {
        "Critical": "Highest",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Lowest",
    }.get(severity, "Medium")


def format_finding_as_jira_issue(finding: Finding, state: ScanState, project_key: str = "SEC") -> dict[str, Any]:
    """Format finding as a standard JIRA issue import JSON object."""
    sev = finding.severity.value
    guide = get_remediation_guide(finding.category or finding.vuln_type)
    
    description = f"""*Vulnerability:* {finding.title}
*Severity:* {sev}
*Classification:* {finding.classification.value} (Confidence: {finding.confidence_score}/10)
*Target URL:* {finding.target}
*Affected Parameter:* {finding.parameter or 'None'}
*CWE:* {finding.cwe or 'None'} | *CVSS:* {finding.cvss or 'N/A'}

h3. Description
{finding.description or guide.get('summary', '')}

h3. Evidence Excerpt
{{code}}
{finding.evidence or 'No raw payload stored'}
{{code}}

h3. Remediation Checklist
{chr(10).join(f"* {item}" for item in guide.get('prevention_checklist', []))}

----
_Created automatically by CENTRIX Scanner for scan {state.id}._
"""

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[CENTRIX] [{sev}] {finding.title}",
            "description": description,
            "issuetype": {"name": "Security Vulnerability"},
            "priority": {"name": _map_jira_priority(sev)},
            "labels": [
                "security",
                "centrix",
                f"cwe-{finding.cwe or 'unknown'}".lower(),
                f"severity-{sev.lower()}",
            ],
            "customfield_target_url": finding.target,
        }
    }


def build_jira_export_bundle(state: ScanState, findings: list[Finding], project_key: str = "SEC") -> str:
    """Export all findings as a JIRA REST API compatible bulk import format."""
    return json.dumps({
        "generator": "CENTRIX JIRA Exporter v4.0",
        "scan_id": state.id,
        "target": state.config.target,
        "exported_at": datetime.utcnow().isoformat(),
        "issueUpdates": [format_finding_as_jira_issue(f, state, project_key) for f in findings],
    }, indent=2)
